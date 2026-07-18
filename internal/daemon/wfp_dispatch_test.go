// SPDX-License-Identifier: MIT

package daemon

import (
	"net"
	"testing"
)

// TestServer_WFPApplyRevoke_Dispatch verifies the broker IPC plumbing:
// a dizgin client sends TypeWFPApply / TypeWFPRevoke, the server routes to
// the netfilter package, and a single TypeStatus response comes back and
// closes the connection.
//
// It does NOT assert that filters were actually installed — that requires
// an elevated host with the BFE service and is covered by the netfilter
// package's live round-trip test. On a non-elevated host (and on
// non-Windows) netfilter.Apply returns an error, which the handler turns
// into resp.Error; either outcome proves the dispatch path works.
func TestServer_WFPApplyRevoke_Dispatch(t *testing.T) {
	srv := NewServer()
	addr := tempSocketPath(t)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.listener = l
	go srv.Serve()
	defer srv.Close() //nolint:errcheck

	// wfp_apply → one TypeStatus response, connection closes.
	apply := roundTrip(t, addr, Message{
		Type: TypeWFPApply,
		ID:   "sess-1",
		Path: `C:\Windows\System32\cmd.exe`,
		Args: []string{"203.0.113.5"},
	})
	if apply.Type != TypeStatus {
		t.Errorf("wfp_apply resp type = %q, want %q", apply.Type, TypeStatus)
	}

	// wfp_revoke → one TypeStatus response (ok or error), connection closes.
	revoke := roundTrip(t, addr, Message{Type: TypeWFPRevoke, ID: "sess-1"})
	if revoke.Type != TypeStatus {
		t.Errorf("wfp_revoke resp type = %q, want %q", revoke.Type, TypeStatus)
	}
}

// roundTrip dials addr, sends one message, decodes one response, closes.
func roundTrip(t *testing.T, addr string, msg Message) Message {
	t.Helper()
	nc, err := dialTCP(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer nc.Close() //nolint:errcheck
	if err := NewEncoder(nc).Encode(msg); err != nil {
		t.Fatalf("encode %s: %v", msg.Type, err)
	}
	var resp Message
	if err := NewDecoder(nc).Decode(&resp); err != nil {
		t.Fatalf("decode %s response: %v", msg.Type, err)
	}
	return resp
}
