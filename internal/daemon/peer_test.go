// SPDX-License-Identifier: MIT

package daemon

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestIsPrivilegedType verifies that the privileged-message classifier
// covers the expected set of admin-only types and leaves session-lifecycle
// types as non-privileged.
func TestIsPrivilegedType(t *testing.T) {
	privileged := []MessageType{
		TypeShutdown, TypeLaunch, TypeRemoteCommand,
		TypeWFPApply, TypeWFPRevoke,
	}
	for _, mt := range privileged {
		if !isPrivilegedType(mt) {
			t.Errorf("isPrivilegedType(%q) = false, want true", mt)
		}
	}

	nonPrivileged := []MessageType{
		TypeRegister, TypeHeartbeat, TypeDeregister,
		TypeCommand, TypeStatus, TypeQueryStatus,
	}
	for _, mt := range nonPrivileged {
		if isPrivilegedType(mt) {
			t.Errorf("isPrivilegedType(%q) = true, want false", mt)
		}
	}
}

// TestPeerUID_SameUser_UnixSocket verifies that peerUID correctly returns the
// current user's UID on a unix-domain socket connection, and that the same-user
// check in handleConn does not block legitimate same-user clients (SEC-01 regression).
//
// Skipped on Windows (named-pipe DACL is the gate there) and on platforms
// where peerUID is not implemented (peer_other.go stub).
func TestPeerUID_SameUser_UnixSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("peerUID not implemented on Windows; DACL is the authorization gate")
	}

	// Create a temporary unix socket. Deliberately not t.TempDir(): on macOS
	// its per-test subdirectory pushes the path past the 104-byte sun_path
	// limit (bind fails with EINVAL), so use a short name directly under the
	// system temp dir.
	sockPath := filepath.Join(os.TempDir(), fmt.Sprintf("peer-%d.sock", os.Getpid()))
	t.Cleanup(func() { _ = os.Remove(sockPath) })

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	if err := os.Chmod(sockPath, 0600); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	// Accept one connection in a goroutine.
	type result struct {
		uid uint32
		ok  bool
	}
	ch := make(chan result, 1)
	go func() {
		nc, err := ln.Accept()
		if err != nil {
			ch <- result{}
			return
		}
		defer nc.Close() //nolint:errcheck
		uid, ok := peerUID(nc)
		ch <- result{uid, ok}
	}()

	// Connect from this process (same user).
	client, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close() //nolint:errcheck

	// On platforms where peerUID is not implemented (peer_other.go), ok=false
	// and the check is skipped — the test still passes because the socket's
	// 0600 permission is the primary gate on those platforms.
	select {
	case r := <-ch:
		if !r.ok {
			// Not implemented on this platform; skip the UID assertion.
			t.Skip("peerUID not available on this platform; transport-level 0600 is the gate")
		}
		wantUID := uint32(os.Geteuid())
		if r.uid != wantUID {
			t.Errorf("peerUID: got %d, want %d (daemon uid)", r.uid, wantUID)
		}
		// Verify that the same-user check would pass (the core regression).
		if r.uid != daemonUID() {
			t.Errorf("same-user flow would be rejected: peerUID %d != daemonUID %d", r.uid, daemonUID())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peerUID test timed out")
	}
}

// TestServer_SameUser_PrivilegedMessage_Allowed verifies that a same-user client
// can send privileged message types (TypeShutdown) without being rejected.
// This is the primary SEC-01 regression test: the peer-uid check must not
// block legitimate same-user flows.
//
// Uses TCP for cross-platform compatibility; peerUID returns ok=false on TCP
// so the UID check is skipped and the message is handled normally.
func TestServer_SameUser_PrivilegedMessage_Allowed(t *testing.T) {
	srv := NewServer()
	addr := tempSocketPath(t)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.listener = l
	go srv.Serve()
	// Do not defer Close; the shutdown message will close it.

	nc, err := dialTCP(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer nc.Close() //nolint:errcheck

	enc := NewEncoder(nc)
	dec := NewDecoder(nc)

	// TypeShutdown is privileged; on TCP (hasPeerUID=false) it must be
	// handled, not rejected.
	if err := enc.Encode(Message{Type: TypeShutdown}); err != nil {
		t.Fatalf("encode shutdown: %v", err)
	}

	nc.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	var resp Message
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode shutdown ack: %v", err)
	}
	if resp.Status != "shutting_down" {
		t.Errorf("shutdown ack status: want %q, got %q", "shutting_down", resp.Status)
	}
}
