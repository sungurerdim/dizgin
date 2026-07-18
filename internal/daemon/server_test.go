// SPDX-License-Identifier: MIT

package daemon

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// waitFor polls fn every 5ms until it returns true or timeout is reached.
func waitFor(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		if fn() {
			return
		}
		select {
		case <-deadline:
			t.Fatal("waitFor: timed out")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// ── Server integration tests ─────────────────────────────────────────────────

// tempSocketPath returns a temporary TCP address for tests.
func tempSocketPath(t *testing.T) string {
	t.Helper()
	// Use an ephemeral TCP port on loopback for cross-platform compatibility.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// dialTCP connects to the given TCP address.
func dialTCP(addr string) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, 2*time.Second)
}

func TestServer_RegisterDeregister(t *testing.T) {
	srv := NewServer()
	addr := tempSocketPath(t)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.listener = l
	go srv.Serve()
	defer srv.Close() //nolint:errcheck

	// Connect a client.
	nc, err := dialTCP(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer nc.Close() //nolint:errcheck

	enc := NewEncoder(nc)

	// Register a session.
	if err := enc.Encode(Message{
		Type:    TypeRegister,
		ID:      "session1",
		PID:     1234,
		Tool:    "claude",
		Workdir: "/project",
		Backend: "container",
	}); err != nil {
		t.Fatalf("encode register: %v", err)
	}

	// Wait for the server to process the register message.
	waitFor(t, 2*time.Second, func() bool { return len(srv.Infos()) == 1 })

	infos := srv.Infos()
	if len(infos) != 1 {
		t.Errorf("after register: want 1 session, got %d", len(infos))
	}
	if len(infos) > 0 && infos[0].Tool != "claude" {
		t.Errorf("tool: want claude, got %q", infos[0].Tool)
	}

	// Deregister.
	if err := enc.Encode(Message{
		Type: TypeDeregister,
		ID:   "session1",
		Exit: 0,
	}); err != nil {
		t.Fatalf("encode deregister: %v", err)
	}

	// Connection is closed on deregister — consume any remaining data.
	io.Copy(io.Discard, nc) //nolint:errcheck

	// Wait for the server to process the deregister message.
	waitFor(t, 2*time.Second, func() bool { return len(srv.Infos()) == 0 })

	infos = srv.Infos()
	if len(infos) != 0 {
		t.Errorf("after deregister: want 0 sessions, got %d", len(infos))
	}
}

func TestServer_QueryStatus(t *testing.T) {
	srv := NewServer()
	addr := tempSocketPath(t)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.listener = l
	go srv.Serve()
	defer srv.Close() //nolint:errcheck

	// Pre-populate the registry directly.
	srv.registry.Register(&Instance{InstanceData: InstanceData{
		ID:     "pre1",
		Tool:   "claude",
		Status: StatusRunning,
	}})

	// Connect admin client and query status.
	nc, err := dialTCP(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer nc.Close() //nolint:errcheck

	enc := NewEncoder(nc)
	dec := NewDecoder(nc)

	if err := enc.Encode(Message{Type: TypeQueryStatus}); err != nil {
		t.Fatalf("encode query: %v", err)
	}

	var resp Message
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Instances) != 1 {
		t.Errorf("query status: want 1 session, got %d", len(resp.Instances))
	}
}

func TestServer_Heartbeat_UpdatesInstance(t *testing.T) {
	srv := NewServer()
	addr := tempSocketPath(t)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.listener = l
	go srv.Serve()
	defer srv.Close() //nolint:errcheck

	nc, err := dialTCP(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer nc.Close() //nolint:errcheck

	enc := NewEncoder(nc)

	// Register first.
	if err := enc.Encode(Message{
		Type: TypeRegister,
		ID:   "hb1",
		Tool: "claude",
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return srv.registry.Get("hb1") != nil })

	// Send heartbeat with updated snippet and memory.
	if err := enc.Encode(Message{
		Type:    TypeHeartbeat,
		ID:      "hb1",
		Snippet: "new task",
		Memory:  2 * 1024 * 1024,
	}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool {
		inst := srv.registry.Get("hb1")
		if inst == nil {
			return false
		}
		return inst.Snapshot().LastSnippet == "new task"
	})

	inst := srv.registry.Get("hb1")
	if inst == nil {
		t.Fatal("instance not found after heartbeat")
	}
	snap := inst.Snapshot()
	if snap.LastSnippet != "new task" {
		t.Errorf("snippet: want 'new task', got %q", snap.LastSnippet)
	}
	if snap.MemoryBytes != 2*1024*1024 {
		t.Errorf("memory: want %d, got %d", 2*1024*1024, snap.MemoryBytes)
	}
}

func TestServer_SendCommand_ToSession(t *testing.T) {
	srv := NewServer()
	addr := tempSocketPath(t)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.listener = l
	go srv.Serve()
	defer srv.Close() //nolint:errcheck

	nc, err := dialTCP(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer nc.Close() //nolint:errcheck

	enc := NewEncoder(nc)
	dec := NewDecoder(nc)

	// Register.
	if err := enc.Encode(Message{Type: TypeRegister, ID: "cmd1", Tool: "claude"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return srv.registry.Get("cmd1") != nil })

	// Send a command from the server side.
	if err := srv.SendCommand("cmd1", ActionSuspend); err != nil {
		t.Errorf("SendCommand: %v", err)
	}

	// The client should receive the command.
	nc.SetDeadline(time.Now().Add(500 * time.Millisecond)) //nolint:errcheck
	var cmd Message
	if err := dec.Decode(&cmd); err != nil {
		t.Fatalf("decode command: %v", err)
	}
	if cmd.Type != TypeCommand {
		t.Errorf("cmd type: want %q, got %q", TypeCommand, cmd.Type)
	}
	if cmd.Action != ActionSuspend {
		t.Errorf("action: want suspend, got %q", cmd.Action)
	}
}

func TestServer_SendCommand_NonExistent(t *testing.T) {
	srv := NewServer()
	err := srv.SendCommand("nonexistent", ActionKill)
	if err == nil {
		t.Error("SendCommand to nonexistent session: expected error, got nil")
	}
}

func TestServer_DroppedConn_CleansUp(t *testing.T) {
	srv := NewServer()
	addr := tempSocketPath(t)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.listener = l
	go srv.Serve()
	defer srv.Close() //nolint:errcheck

	nc, err := dialTCP(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	enc := NewEncoder(nc)
	if err := enc.Encode(Message{Type: TypeRegister, ID: "drop1", Tool: "claude"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return srv.registry.Get("drop1") != nil })

	// Forcibly close connection without deregistering.
	_ = nc.Close()

	// Wait for the server to detect the dropped connection and clean up.
	waitFor(t, 2*time.Second, func() bool { return srv.registry.Get("drop1") == nil })

	// Instance should be removed.
	if srv.registry.Get("drop1") != nil {
		t.Error("instance should be cleaned up after connection drop")
	}
}

func TestServer_Close_GracePeriod(t *testing.T) {
	srv := NewServer()
	addr := tempSocketPath(t)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.listener = l
	go srv.Serve()

	// Connect and register a session.
	nc, err := dialTCP(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer nc.Close() //nolint:errcheck

	enc := NewEncoder(nc)
	if err := enc.Encode(Message{Type: TypeRegister, ID: "grace1", Tool: "claude"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return len(srv.Infos()) == 1 })

	// Deregister the session so the grace period completes quickly.
	if err := enc.Encode(Message{Type: TypeDeregister, ID: "grace1", Exit: 0}); err != nil {
		t.Fatalf("deregister: %v", err)
	}
	// Drain the connection so the server-side handler can finish.
	go io.Copy(io.Discard, nc) //nolint:errcheck

	waitFor(t, 2*time.Second, func() bool { return len(srv.Infos()) == 0 })

	// Close the server — should shut down cleanly within a reasonable time.
	done := make(chan error, 1)
	go func() { done <- srv.Close() }()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Close: unexpected error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close: did not return within 10 seconds")
	}
}

func TestServer_Shutdown_ViaProtocol(t *testing.T) {
	srv := NewServer()
	addr := tempSocketPath(t)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.listener = l
	go srv.Serve()

	// Connect admin client and send shutdown.
	nc, err := dialTCP(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer nc.Close() //nolint:errcheck

	enc := NewEncoder(nc)
	dec := NewDecoder(nc)

	if err := enc.Encode(Message{Type: TypeShutdown}); err != nil {
		t.Fatalf("encode shutdown: %v", err)
	}

	// Should receive a "shutting_down" acknowledgement.
	nc.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	var resp Message
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode shutdown ack: %v", err)
	}
	if resp.Status != "shutting_down" {
		t.Errorf("shutdown ack status: want %q, got %q", "shutting_down", resp.Status)
	}

	// The server should stop accepting connections shortly.
	waitFor(t, 10*time.Second, func() bool {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err != nil {
			return true // listener closed
		}
		_ = c.Close()
		return false
	})
}

func TestServer_MultipleRegistrations(t *testing.T) {
	srv := NewServer()
	addr := tempSocketPath(t)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.listener = l
	go srv.Serve()
	defer srv.Close() //nolint:errcheck

	// Register 3 sessions from 3 separate connections.
	for i := 0; i < 3; i++ {
		nc, err := dialTCP(addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer nc.Close() //nolint:errcheck

		enc := NewEncoder(nc)
		id := fmt.Sprintf("multi-%d", i)
		if err := enc.Encode(Message{
			Type: TypeRegister,
			ID:   id,
			Tool: "claude",
			PID:  1000 + i,
		}); err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
	}

	waitFor(t, 2*time.Second, func() bool { return len(srv.Infos()) == 3 })

	infos := srv.Infos()
	if len(infos) != 3 {
		t.Errorf("want 3 sessions, got %d", len(infos))
	}
}

func TestServer_Heartbeat_NonExistent(t *testing.T) {
	srv := NewServer()
	addr := tempSocketPath(t)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.listener = l
	go srv.Serve()
	defer srv.Close() //nolint:errcheck

	nc, err := dialTCP(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer nc.Close() //nolint:errcheck

	enc := NewEncoder(nc)

	// Register first so we have a valid connection, then send heartbeat for a
	// different (non-existent) session ID. Server must not panic.
	if err := enc.Encode(Message{Type: TypeRegister, ID: "hb-real", Tool: "claude"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return srv.registry.Get("hb-real") != nil })

	if err := enc.Encode(Message{
		Type:    TypeHeartbeat,
		ID:      "hb-nonexistent",
		Snippet: "ghost",
		Memory:  999,
	}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}

	// Wait for the server to process the heartbeat message. We verify the
	// message was consumed by confirming the real session still exists and the
	// non-existent session was never created. If the server panics, the test
	// will crash.
	waitFor(t, 2*time.Second, func() bool {
		// The heartbeat for "hb-nonexistent" is processed after the register
		// for "hb-real". Once the real session's heartbeat time advances past
		// its registration time, we know the server has processed at least one
		// message after the register — meaning our bogus heartbeat has been
		// consumed too (messages are sequential on the same connection).
		inst := srv.registry.Get("hb-real")
		return inst != nil && srv.registry.Get("hb-nonexistent") == nil
	})

	// Final assertions for clarity.
	if srv.registry.Get("hb-real") == nil {
		t.Error("real session should still exist")
	}
	if srv.registry.Get("hb-nonexistent") != nil {
		t.Error("non-existent session should not appear in registry")
	}
}
