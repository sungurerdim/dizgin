// SPDX-License-Identifier: MIT

package daemon

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sungurerdim/dizgin/internal/log"
)

// isPrivilegedType returns true for message types that trigger privileged
// daemon actions (shutdown, session launch, remote control, WFP brokering).
// These types must only be accepted from callers that pass the peer-uid check.
func isPrivilegedType(t MessageType) bool {
	switch t {
	case TypeShutdown, TypeLaunch, TypeRemoteCommand, TypeWFPApply, TypeWFPRevoke:
		return true
	}
	return false
}

// Server is the dizgind IPC server. It listens on a platform-specific
// transport (named pipe on Windows, unix socket on Linux/macOS) and manages
// registered sandbox instances.
type Server struct {
	listener net.Listener
	ctx      context.Context
	registry *Registry
	launcher *Launcher
	conns    map[string]*conn
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	connsMu  sync.Mutex
}

// conn wraps a single IPC connection from one dizgin session.
type conn struct {
	nc  net.Conn
	enc *Encoder
	mu  sync.Mutex
}

func (c *conn) send(msg Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enc.Encode(msg)
}

// NewServer creates a Server but does not start listening.
func NewServer() *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		registry: NewRegistry(),
		launcher: NewLauncher(),
		conns:    make(map[string]*conn),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Registry returns the session registry for external use (e.g. REST API).
func (s *Server) Registry() *Registry { return s.registry }

// Launcher returns the session launcher for external use (e.g. REST API).
func (s *Server) Launcher() *Launcher { return s.launcher }

// Listen starts accepting connections on the platform transport.
// It returns immediately; call Serve to handle accepted connections.
func (s *Server) Listen() error {
	l, err := listen()
	if err != nil {
		return fmt.Errorf("daemon: listen: %w", err)
	}
	s.listener = l
	return nil
}

// Serve accepts and handles connections until Close is called.
func (s *Server) Serve() {
	// Heartbeat timeout pruner.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				s.registry.PruneDeadInstances()
			}
		}
	}()

	for {
		nc, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				log.Error("daemon: accept: %v", err)
				continue
			}
		}
		s.wg.Add(1)
		go s.handleConn(nc)
	}
}

// handleConn processes all messages from a single dizgin connection.
//
// IPC command flow and re-entry safety:
// Each connection is handled by exactly one goroutine that reads messages
// sequentially in a loop. There is no concurrent dispatch — a connection
// processes one message at a time before reading the next. Admin commands
// (TypeShutdown, TypeLaunch, TypeRemoteCommand, TypeQueryStatus) and
// container broker requests are single-shot: the handler sends a response
// and returns, closing the connection. Session connections (register →
// heartbeat* → deregister) hold the loop open but still process one
// message per iteration. Because dispatch is sequential per connection and
// state mutations go through the mutex-protected registry, there is no
// risk of re-entrant command processing. Server.SendCommand writes to a
// *different* connection's encoder (protected by conn.mu), so it cannot
// deadlock with the current connection's read loop.
func (s *Server) handleConn(nc net.Conn) {
	defer s.wg.Done()
	defer nc.Close() //nolint:errcheck
	defer func() {
		if r := recover(); r != nil {
			log.Error("daemon: handleConn panic: %v", r)
		}
	}()

	c := &conn{nc: nc, enc: NewEncoder(nc)}
	dec := NewDecoder(nc)

	// Defense-in-depth: verify the connecting process belongs to the same user
	// as the daemon. On Linux this uses SO_PEERCRED; on macOS LOCAL_PEERCRED.
	// On Windows the named-pipe DACL (transport_windows.go:pipeSDDL) already
	// enforces owner-only access at the OS level, so peerUID returns ok=false
	// and the check is skipped — no redundant work needed.
	// peerUID returns (0, false) on platforms where the check is unavailable,
	// so we only enforce when we have a real answer.
	connPeerUID, hasPeerUID := peerUID(nc)
	ownUID := daemonUID()

	// connReadTimeout is the maximum idle time between messages before the
	// connection is considered stale. Heartbeats arrive every 10s, so 60s
	// gives ample margin for transient delays.
	const connReadTimeout = 60 * time.Second

	var sessionID string

	for {
		// Set a read deadline so stale connections don't linger forever.
		// The deadline is reset after every successful decode.
		if err := nc.SetReadDeadline(time.Now().Add(connReadTimeout)); err != nil {
			break
		}

		var msg Message
		if err := dec.Decode(&msg); err != nil {
			// Timeout, EOF, or connection reset — all mean this connection is done.
			break
		}

		// Defense-in-depth: reject privileged message types from connections
		// whose peer UID does not match the daemon's own UID. On platforms
		// where hasPeerUID is false (Windows, unsupported unix), this check
		// is skipped and the transport-layer ACL (DACL / 0600 socket) is the
		// sole gate.
		if hasPeerUID && isPrivilegedType(msg.Type) && connPeerUID != ownUID {
			log.Error("daemon: rejected %s from uid %d (daemon uid %d)", msg.Type, connPeerUID, ownUID)
			_ = c.send(Message{Type: TypeStatus, Error: "unauthorized: uid mismatch"})
			return
		}

		done := s.dispatchMessage(c, &sessionID, msg)
		if done {
			return
		}
	}

	// Clean up if the connection dropped without deregistering.
	if sessionID != "" {
		s.registry.Remove(sessionID)
		s.connsMu.Lock()
		delete(s.conns, sessionID)
		s.connsMu.Unlock()
	}
}

// dispatchMessage routes a single IPC message to the appropriate handler.
// Returns true when handleConn should return (connection is done), false
// to continue reading the next message.
func (s *Server) dispatchMessage(c *conn, sessionID *string, msg Message) (done bool) {
	switch msg.Type {
	case TypeRegister:
		s.handleRegister(c, sessionID, msg)
	case TypeHeartbeat:
		s.handleHeartbeat(msg)
	case TypeDeregister:
		s.handleDeregister(c, msg)
		return true
	case TypeQueryStatus:
		s.handleQueryStatus(c)
		return true
	case TypeShutdown:
		s.handleShutdown(c)
		return true
	case TypeLaunch:
		s.handleLaunch(c, msg)
		return true
	case TypeRemoteCommand:
		s.handleRemoteCommand(c, msg)
		return true
	default:
		if s.handlePlatformMessage(c, msg) {
			return true
		}
		// Unknown or platform-unsupported type: respond with an error instead
		// of silently dropping, so the client fails fast rather than blocking
		// until its read deadline.
		log.Error("daemon: unsupported message type %q", msg.Type)
		_ = c.send(Message{Type: TypeStatus, Error: fmt.Sprintf("unsupported message type %q on this platform", msg.Type)})
		return true
	}
	return false
}

// handleRegister processes a TypeRegister message: records the new session
// in the registry and wires the connection for future command delivery.
func (s *Server) handleRegister(c *conn, sessionID *string, msg Message) {
	*sessionID = msg.ID
	inst := &Instance{InstanceData: InstanceData{
		ID:      msg.ID,
		PID:     msg.PID,
		Tool:    msg.Tool,
		Workdir: msg.Workdir,
		Backend: msg.Backend,
		Status:  StatusRunning,
		Args:    msg.Args,
	}}
	s.registry.Register(inst)
	s.connsMu.Lock()
	s.conns[*sessionID] = c
	s.connsMu.Unlock()
}

// handleHeartbeat processes a TypeHeartbeat message: updates the session record.
func (s *Server) handleHeartbeat(msg Message) {
	s.registry.Update(msg.ID, msg)
}

// handleDeregister processes a TypeDeregister message: marks the session dead
// and removes its connection entry. The caller closes the connection.
func (s *Server) handleDeregister(_ *conn, msg Message) {
	if inst := s.registry.Remove(msg.ID); inst != nil {
		inst.mu.Lock()
		inst.ExitCode = msg.Exit
		inst.Status = StatusDead
		inst.mu.Unlock()
	}
	s.connsMu.Lock()
	delete(s.conns, msg.ID)
	s.connsMu.Unlock()
}

// handleQueryStatus responds with a snapshot of all active sessions and signals done.
func (s *Server) handleQueryStatus(c *conn) {
	if err := c.send(Message{
		Type:      TypeStatus,
		Instances: s.registry.Infos(),
	}); err != nil {
		log.Debug("send status response: %v", err)
	}
}

// handleShutdown acknowledges the shutdown request and initiates graceful stop.
func (s *Server) handleShutdown(c *conn) {
	if err := c.send(Message{Type: TypeStatus, Status: "shutting_down"}); err != nil {
		log.Debug("send shutdown ack: %v", err)
	}
	go func() {
		if err := s.Close(); err != nil {
			log.Debug("graceful shutdown: %v", err)
		}
	}()
}

// Infos returns a snapshot of all active sessions.
// It satisfies the tui.SessionSource interface.
func (s *Server) Infos() []InstanceInfo {
	return s.registry.Infos()
}

// handleLaunch processes a TypeLaunch message (admin/TUI session launch request).
func (s *Server) handleLaunch(c *conn, msg Message) {
	pid, err := s.launcher.LaunchSession(msg.Tool, msg.Workdir, msg.Args)
	var resp Message
	if err != nil {
		resp = Message{Type: TypeStatus, Error: err.Error()}
	} else {
		resp = Message{Type: TypeStatus, PID: pid}
	}
	if sendErr := c.send(resp); sendErr != nil {
		log.Debug("send launch response: %v", sendErr)
	}
}

// handleRemoteCommand processes a TypeRemoteCommand message (remote TUI session command).
func (s *Server) handleRemoteCommand(c *conn, msg Message) {
	var resp Message
	if msg.Action == ActionRestart {
		killFn := func(id string) error {
			return s.SendCommand(id, ActionKill)
		}
		pid, err := s.launcher.RestartSession(s.registry, msg.ID, killFn)
		if err != nil {
			resp = Message{Type: TypeStatus, Error: err.Error()}
		} else {
			resp = Message{Type: TypeStatus, PID: pid}
		}
	} else {
		if err := s.SendCommand(msg.ID, msg.Action); err != nil {
			resp = Message{Type: TypeStatus, Error: err.Error()}
		} else {
			resp = Message{Type: TypeStatus, Status: "ok"}
		}
	}
	if err := c.send(resp); err != nil {
		log.Debug("send remote command response: %v", err)
	}
}

// SendCommand delivers a command message to the session identified by id.
// Returns an error if the session is not connected.
func (s *Server) SendCommand(id string, action CommandAction) error {
	s.connsMu.Lock()
	c, ok := s.conns[id]
	s.connsMu.Unlock()
	if !ok {
		return fmt.Errorf("daemon: session %q not connected", id)
	}
	if err := c.send(Message{Type: TypeCommand, ID: id, Action: action}); err != nil {
		s.connsMu.Lock()
		delete(s.conns, id)
		s.connsMu.Unlock()
		return err
	}
	return nil
}

// Close shuts down the server gracefully in four phases:
//
//  1. Notify: sends a TypeShutdown message to every connected session (best-effort,
//     1-second write deadline per connection so unresponsive clients don't block).
//  2. Grace period: polls the registry every 100ms for up to 5 seconds, waiting for
//     sessions to deregister voluntarily. If sessions remain after the 5-second
//     timeout, they are abandoned (their connections will be closed in step 4).
//  3. Cleanup: calls cleanupAllBrokered() to tear down any brokered containers.
//  4. Teardown: closes the listener (unblocking Accept in Serve), cancels the server
//     context (stopping the heartbeat pruner), and waits for all connection handler
//     goroutines to finish via wg.Wait().
func (s *Server) Close() error {
	// Signal active connections that shutdown is beginning.
	s.connsMu.Lock()
	for _, c := range s.conns {
		// Best-effort notify — don't block on unresponsive clients.
		_ = c.nc.SetWriteDeadline(time.Now().Add(1 * time.Second))
		_ = c.send(Message{Type: TypeShutdown})
	}
	s.connsMu.Unlock()

	// Grace period: wait for active sessions to deregister.
	graceCtx, graceCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer graceCancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-graceCtx.Done():
		case <-ticker.C:
			if s.registry.Count() != 0 {
				continue
			}
		}
		break
	}

	err := s.listener.Close() // unblock Accept()
	s.cancel()                // signal context cancellation
	s.wg.Wait()
	return err
}
