// SPDX-License-Identifier: MIT

package daemon

import (
	"net"
	"testing"
	"time"
)

// TST-18: admin.go — QueryStatus / IsDaemonRunning / daemonCall.
//
// The package-level dial() function is a concrete function (not a variable),
// so we cannot swap it out without modifying source files. Instead:
//
//  - "daemon-down" paths (IsDaemonRunning=false, QueryStatus error) are
//    tested by relying on the real dial returning an error when no server
//    is listening on the platform transport. These are always true in CI
//    (no dizgind daemon running).
//
//  - Request/response round-trips for QueryStatus are tested via the
//    in-process server pattern from server_test.go, using the lower-level
//    encode/decode helpers to simulate what daemonCall does over TCP — so we
//    verify the wire contract without needing a named-pipe override.

// ── IsDaemonRunning ───────────────────────────────────────────────────────────

// TestIsDaemonRunning_NoDaemon verifies that IsDaemonRunning returns false when
// no dizgind daemon is listening. This is always true in the unit-test
// environment (no daemon started).
func TestIsDaemonRunning_NoDaemon(t *testing.T) {
	// If a daemon happens to be running (developer machine with dizgind
	// started), skip rather than falsely fail.
	if IsDaemonRunning() {
		t.Skip("dizgind daemon is running — skipping daemon-down test")
	}
	// Re-invoke to confirm the result is stable.
	if IsDaemonRunning() {
		t.Error("IsDaemonRunning: want false when no daemon is running, got true")
	}
}

// ── QueryStatus daemon-down path ──────────────────────────────────────────────

func TestQueryStatus_DaemonDown(t *testing.T) {
	if IsDaemonRunning() {
		t.Skip("dizgind daemon is running — skipping daemon-down test")
	}
	_, err := QueryStatus()
	if err == nil {
		t.Error("QueryStatus with no daemon: want error, got nil")
	}
}

// ── In-process wire round-trip for QueryStatus semantics ─────────────────────
//
// We spin up the in-process Server on TCP (same pattern as server_test.go)
// and exercise the TypeQueryStatus / TypeStatus wire exchange directly,
// verifying the contract that daemonCall relies on.

func TestAdminWire_QueryStatusRoundTrip(t *testing.T) {
	srv := NewServer()
	addr := tempSocketPath(t)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.listener = l
	go srv.Serve()
	defer srv.Close() //nolint:errcheck

	// Pre-populate two sessions so the response is non-trivial.
	srv.registry.Register(&Instance{InstanceData: InstanceData{
		ID:     "admin-sess-1",
		Tool:   "claude",
		Status: StatusRunning,
	}})
	srv.registry.Register(&Instance{InstanceData: InstanceData{
		ID:     "admin-sess-2",
		Tool:   "cursor",
		Status: StatusRunning,
	}})

	// Open an admin connection and send TypeQueryStatus (exactly what daemonCall does).
	nc, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial test server: %v", err)
	}
	defer nc.Close() //nolint:errcheck

	enc := NewEncoder(nc)
	dec := NewDecoder(nc)

	if err := enc.Encode(Message{Type: TypeQueryStatus}); err != nil {
		t.Fatalf("encode query: %v", err)
	}

	nc.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	var resp Message
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.Error != "" {
		t.Fatalf("server returned error: %s", resp.Error)
	}
	if len(resp.Instances) != 2 {
		t.Errorf("Sessions: want 2, got %d", len(resp.Instances))
	}

	found := map[string]bool{}
	for _, s := range resp.Instances {
		found[s.ID] = true
	}
	for _, id := range []string{"admin-sess-1", "admin-sess-2"} {
		if !found[id] {
			t.Errorf("session %q missing from QueryStatus response", id)
		}
	}
}

func TestAdminWire_QueryStatusEmptyRegistry(t *testing.T) {
	srv := NewServer()
	addr := tempSocketPath(t)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.listener = l
	go srv.Serve()
	defer srv.Close() //nolint:errcheck

	nc, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer nc.Close() //nolint:errcheck

	enc := NewEncoder(nc)
	dec := NewDecoder(nc)

	if err := enc.Encode(Message{Type: TypeQueryStatus}); err != nil {
		t.Fatalf("encode: %v", err)
	}

	nc.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	var resp Message
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Instances) != 0 {
		t.Errorf("empty registry: want 0 sessions, got %d", len(resp.Instances))
	}
}

func TestAdminWire_SessionFieldsPreserved(t *testing.T) {
	srv := NewServer()
	addr := tempSocketPath(t)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.listener = l
	go srv.Serve()
	defer srv.Close() //nolint:errcheck

	srv.registry.Register(&Instance{InstanceData: InstanceData{
		ID:      "fields-test",
		PID:     42000,
		Tool:    "claude",
		Workdir: `D:\dev\project`,
		Backend: "restricted",
		Status:  StatusRunning,
	}})

	nc, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer nc.Close() //nolint:errcheck

	enc := NewEncoder(nc)
	dec := NewDecoder(nc)

	if err := enc.Encode(Message{Type: TypeQueryStatus}); err != nil {
		t.Fatalf("encode: %v", err)
	}

	nc.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	var resp Message
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(resp.Instances) != 1 {
		t.Fatalf("want 1 session, got %d", len(resp.Instances))
	}
	s := resp.Instances[0]
	if s.ID != "fields-test" {
		t.Errorf("ID: want fields-test, got %q", s.ID)
	}
	if s.PID != 42000 {
		t.Errorf("PID: want 42000, got %d", s.PID)
	}
	if s.Tool != "claude" {
		t.Errorf("Tool: want claude, got %q", s.Tool)
	}
	if s.Backend != "restricted" {
		t.Errorf("Backend: want restricted, got %q", s.Backend)
	}
}
