// SPDX-License-Identifier: MIT

// Package daemon provides the IPC client and server for dizgin sessions.
//
// Error handling policy for Client methods:
//
//   - Heartbeat / HeartbeatWithMetrics: fire-and-forget. Encode errors are
//     silently ignored because heartbeats are periodic and non-blocking; a
//     single missed heartbeat has no user-visible effect.
//
//   - SendCommand: errors are returned to the caller. Command delivery is
//     critical — the caller must know whether the daemon received the message.
//
//   - Deregister: best-effort. The process is already exiting, so a failed
//     deregister is logged (via the nolint:errcheck on Encode) but is not
//     fatal. The daemon will expire the session on heartbeat timeout anyway.
package daemon

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// ConnectionState describes the lifecycle of a daemon client connection.
type ConnectionState int

const (
	// StateDiscovery means no connection has been established yet.
	StateDiscovery ConnectionState = iota
	// StateConnected means a live connection to the daemon exists.
	StateConnected
	// StateReconnect means the connection was lost and a reconnect is pending.
	StateReconnect
)

// CommandHandlerFunc is called when the daemon sends a command to this session.
type CommandHandlerFunc func(action CommandAction)

// Client is the dizgin-side IPC client. It registers the session with the
// daemon and sends periodic heartbeats.
type Client struct {
	circuitUntil   time.Time
	enc            *Encoder
	conn           net.Conn
	closeCh        chan struct{}
	commandHandler CommandHandlerFunc
	backend        string
	sessionID      string
	workdir        string
	tool           string
	wg             sync.WaitGroup
	closeOnce      sync.Once
	state          ConnectionState
	pid            int
	dialFails      int
	mu             sync.Mutex
	circuitOpen    bool
}

// NewClient creates a Client for the given session parameters.
func NewClient(sessionID, tool, workdir, backend string, pid int) *Client {
	return &Client{
		sessionID: sessionID,
		tool:      tool,
		workdir:   workdir,
		backend:   backend,
		pid:       pid,
		state:     StateDiscovery,
		closeCh:   make(chan struct{}),
	}
}

// SetCommandHandler registers a function to be called when the daemon sends a command.
func (c *Client) SetCommandHandler(fn CommandHandlerFunc) {
	c.mu.Lock()
	c.commandHandler = fn
	c.mu.Unlock()
}

// Start begins connecting to the daemon and sending heartbeats.
// It runs in the background; call Close to stop it.
func (c *Client) Start() {
	c.wg.Add(1)
	go c.loop()
}

// Heartbeat updates the heartbeat snippet. It is safe to call concurrently.
func (c *Client) Heartbeat(status, snippet string) {
	c.mu.Lock()
	enc := c.enc
	c.mu.Unlock()
	if enc == nil {
		return
	}
	enc.Encode(Message{ //nolint:errcheck
		Type:    TypeHeartbeat,
		ID:      c.sessionID,
		Status:  status,
		Snippet: RedactSnippet(snippet),
	})
}

// HeartbeatWithMetrics sends a heartbeat with resource metrics from the monitor.
func (c *Client) HeartbeatWithMetrics(status, snippet string, mem uint64, cpu float64, pids int, ioR, ioW, disk uint64, uptime int64, threads, handles int, children []int) {
	c.mu.Lock()
	enc := c.enc
	c.mu.Unlock()
	if enc == nil {
		return
	}
	enc.Encode(Message{ //nolint:errcheck
		Type:        TypeHeartbeat,
		ID:          c.sessionID,
		Status:      status,
		Snippet:     RedactSnippet(snippet),
		Memory:      mem,
		CPU:         cpu,
		PIDs:        pids,
		IORead:      ioR,
		IOWrite:     ioW,
		DiskUsage:   disk,
		Uptime:      uptime,
		ThreadCount: threads,
		HandleCount: handles,
		ChildPIDs:   children,
	})
}

// Deregister sends a deregister message and stops the client.
func (c *Client) Deregister(exitCode int) {
	c.mu.Lock()
	enc := c.enc
	c.mu.Unlock()
	if enc != nil {
		enc.Encode(Message{ //nolint:errcheck
			Type: TypeDeregister,
			ID:   c.sessionID,
			Exit: exitCode,
		})
	}
	c.Close()
}

// Close stops background goroutines. It is safe to call multiple times
// and concurrently from different goroutines.
//
// Winio named pipe reads occasionally ignore Close() — the read blocks
// indefinitely in the Windows kernel. SetReadDeadline(now) forces those
// reads to return immediately so handleIncomingCommands unblocks and
// wg.Wait() can return. Without this, Close could hang forever during
// process teardown when the daemon was killed ungracefully.
func (c *Client) Close() {
	c.closeOnce.Do(func() {
		close(c.closeCh)
		c.mu.Lock()
		conn := c.conn
		c.mu.Unlock()
		if conn != nil {
			if d, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
				d.SetReadDeadline(time.Now()) //nolint:errcheck
			}
			conn.Close() //nolint:errcheck
		}
	})
	c.wg.Wait()
}

// circuitCheck returns true if the circuit breaker allows a connection attempt.
func (c *Client) circuitCheck() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.circuitOpen {
		if time.Now().Before(c.circuitUntil) {
			return false
		}
		c.circuitOpen = false // half-open: allow one attempt
	}
	return true
}

// recordDialFailure updates circuit breaker state after a failed dial.
func (c *Client) recordDialFailure() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dialFails++
	if c.dialFails >= 5 {
		backoff := 30 * time.Second
		if c.dialFails < 10 {
			backoff = time.Duration(c.dialFails*6) * time.Second
		}
		c.circuitOpen = true
		c.circuitUntil = time.Now().Add(backoff)
	}
}

// registerWithDaemon sends the register message over an established connection.
func (c *Client) registerWithDaemon(enc *Encoder) error {
	return enc.Encode(Message{
		Type:    TypeRegister,
		ID:      c.sessionID,
		PID:     c.pid,
		Tool:    c.tool,
		Workdir: c.workdir,
		Backend: c.backend,
	})
}

// handleIncomingCommands reads commands from the daemon and dispatches them.
func (c *Client) handleIncomingCommands(nc net.Conn) {
	defer c.wg.Done()
	defer func() {
		nc.Close() //nolint:errcheck
		c.mu.Lock()
		c.enc = nil
		c.conn = nil
		c.state = StateReconnect
		c.mu.Unlock()
	}()
	dec := NewDecoder(nc)
	for {
		var msg Message
		if err := dec.Decode(&msg); err != nil {
			// Swallow expected shutdown noise:
			//   io.EOF        — daemon closed the pipe
			//   pipe closed   — Windows-specific named-pipe shutdown
			//   i/o timeout   — Close() called SetReadDeadline(now) to
			//                   unblock a parked Windows pipe read
			// Anything else is a real surprise and worth logging.
			if c.shuttingDown() || err == io.EOF || isPipeClosedError(err) || isTimeoutError(err) {
				return
			}
			fmt.Fprintf(os.Stderr, brand.Name+": daemon: recv: %v\n", err)
			return
		}
		if msg.Type == TypeCommand {
			c.mu.Lock()
			fn := c.commandHandler
			c.mu.Unlock()
			if fn != nil {
				fn(msg.Action)
			}
		}
	}
}

// shuttingDown reports whether Close has been called. Reads from the
// registration pipe after Close() are expected to return errors and
// must not log them as if they were unexpected.
func (c *Client) shuttingDown() bool {
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

// isTimeoutError reports whether err is a net.Error with Timeout()=true.
// Windows named pipes return os.ErrDeadlineExceeded once the read deadline
// passes, which is the path Close() uses to unblock parked reads.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	type timeouter interface{ Timeout() bool }
	if t, ok := err.(timeouter); ok && t.Timeout() {
		return true
	}
	return false
}

const (
	dialTimeout     = 2 * time.Second
	heartbeatPeriod = 10 * time.Second
	discoveryPeriod = 5 * time.Second
)

// tryConnect attempts to dial the daemon, register, and start the command handler.
// Returns a new heartbeat ticker on success, or nil on failure.
func (c *Client) tryConnect() *time.Ticker {
	if !c.circuitCheck() {
		return nil
	}

	nc, err := dial(dialTimeout)
	if err != nil {
		c.recordDialFailure()
		return nil
	}
	c.mu.Lock()
	c.dialFails = 0
	c.circuitOpen = false
	c.mu.Unlock()

	enc := NewEncoder(nc)
	if err = c.registerWithDaemon(enc); err != nil {
		nc.Close() //nolint:errcheck
		return nil
	}

	c.mu.Lock()
	c.enc = enc
	c.conn = nc
	c.state = StateConnected
	c.mu.Unlock()

	c.wg.Add(1)
	go c.handleIncomingCommands(nc)

	return time.NewTicker(heartbeatPeriod)
}

// loop is the main connection + heartbeat goroutine.
func (c *Client) loop() {
	defer c.wg.Done()

	discoveryTicker := time.NewTicker(discoveryPeriod)
	defer discoveryTicker.Stop()

	heartbeatTicker := c.tryConnect()

	for {
		var hbC <-chan time.Time
		if heartbeatTicker != nil {
			hbC = heartbeatTicker.C
		}
		select {
		case <-c.closeCh:
			if heartbeatTicker != nil {
				heartbeatTicker.Stop()
			}
			return

		case <-discoveryTicker.C:
			c.mu.Lock()
			state := c.state
			c.mu.Unlock()
			if state != StateConnected {
				if heartbeatTicker != nil {
					heartbeatTicker.Stop()
				}
				heartbeatTicker = c.tryConnect()
			}

		case <-hbC:
			c.Heartbeat(string(StatusRunning), "")
		}
	}
}

// isPipeClosedError returns true for errors that indicate the named pipe or
// socket was closed by the remote end. On Windows, pipe teardown produces
// "file has already been closed" instead of io.EOF.
func isPipeClosedError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "file has already been closed") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "use of closed network connection")
}

// SendCommand is a convenience wrapper used in tests.
func (c *Client) SendCommand(action CommandAction) error {
	c.mu.Lock()
	enc := c.enc
	c.mu.Unlock()
	if enc == nil {
		return fmt.Errorf("client: not connected")
	}
	return enc.Encode(Message{Type: TypeCommand, ID: c.sessionID, Action: action})
}
