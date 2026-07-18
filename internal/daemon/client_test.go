// SPDX-License-Identifier: MIT

package daemon

import (
	"sync/atomic"
	"testing"
)

func TestClient_NewClient(t *testing.T) {
	c := NewClient("sess1", "claude", "/project", "container", 1234)
	if c.sessionID != "sess1" {
		t.Errorf("sessionID: %q", c.sessionID)
	}
	if c.tool != "claude" {
		t.Errorf("tool: %q", c.tool)
	}
	if c.state != StateDiscovery {
		t.Errorf("initial state: %v", c.state)
	}
}

func TestClient_HeartbeatWithMetrics_NotConnected(t *testing.T) {
	c := NewClient("sess2", "claude", "/project", "container", 1234)
	// Should not panic when not connected.
	c.HeartbeatWithMetrics("running", "", 1024, 5.0, 2, 100, 200, 300, 10, 4, 8, nil)
}

func TestClient_Heartbeat_NotConnected(t *testing.T) {
	c := NewClient("sess3", "claude", "/project", "container", 1234)
	// Should not panic when not connected.
	c.Heartbeat("running", "test snippet")
}

func TestClient_Deregister_NotConnected(t *testing.T) {
	c := NewClient("sess4", "claude", "/project", "container", 1234)
	// Should not panic.
	c.Deregister(0)
}

func TestClient_Close_Idempotent(t *testing.T) {
	c := NewClient("sess5", "claude", "/project", "container", 1234)
	c.Start()
	c.Close()
	c.Close() // second close should not panic
}

func TestClient_SetCommandHandler(t *testing.T) {
	c := NewClient("sess6", "claude", "/project", "container", 1234)
	var called atomic.Bool
	c.SetCommandHandler(func(action CommandAction) {
		called.Store(true)
	})
	c.mu.Lock()
	fn := c.commandHandler
	c.mu.Unlock()
	if fn == nil {
		t.Error("handler not set")
	}
}

func TestClient_SendCommand_NotConnected(t *testing.T) {
	c := NewClient("sess7", "claude", "/project", "container", 1234)
	err := c.SendCommand(ActionSuspend)
	if err == nil {
		t.Error("expected error when not connected")
	}
}
