// SPDX-License-Identifier: MIT

//go:build windows

package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseStagingSessionID_Valid(t *testing.T) {
	pid, ok := parseStagingSessionID("12345-1700000000123456789")
	if !ok {
		t.Fatal("valid session id should parse")
	}
	if pid != 12345 {
		t.Errorf("pid: got %d, want 12345", pid)
	}
}

func TestParseStagingSessionID_Invalid(t *testing.T) {
	cases := []string{
		"",
		"not-a-session",
		"12345",         // no suffix
		"abc-123",       // non-digit pid
		"12345-notnano", // non-digit nano
		"0-123",         // pid <= 0
		"-123",          // empty pid
	}
	for _, c := range cases {
		if pid, ok := parseStagingSessionID(c); ok {
			t.Errorf("%q should not parse, got pid=%d", c, pid)
		}
	}
}

func TestIsProcessAlive_SelfPID(t *testing.T) {
	if !isProcessAlive(os.Getpid()) {
		t.Error("current process should be alive")
	}
}

func TestIsProcessAlive_DeadPID(t *testing.T) {
	// A PID in the tens of billions is guaranteed to be unused.
	if isProcessAlive(4294967000) {
		t.Error("oversized PID should not report alive")
	}
}

// TestCleanupStagingRoot_RemovesDeadSession creates a fake staging dir that
// belongs to a non-existent PID and is older than stagingOrphanMaxAge; the
// cleanup pass must delete it. A second dir tied to the current PID is
// kept even though it's old enough, because the owning process is still
// alive.
func TestCleanupStagingRoot_RemovesDeadSession(t *testing.T) {
	root := t.TempDir()

	dead := filepath.Join(root, "4294967000-1")
	live := filepath.Join(root, "-myself-placeholder")
	_ = live // placeholder to satisfy the declared-but-unused check

	if err := os.MkdirAll(dead, 0o755); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-2 * stagingOrphanMaxAge)
	if err := os.Chtimes(dead, past, past); err != nil {
		t.Fatal(err)
	}
	// A session owned by the current process, also old — must survive
	// because the PID is alive.
	ownPID := os.Getpid()
	aliveDir := filepath.Join(root, formatOwn(ownPID))
	if err := os.MkdirAll(aliveDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(aliveDir, past, past); err != nil {
		t.Fatal(err)
	}

	cleanupStagingRoot(root)

	if _, err := os.Stat(dead); !os.IsNotExist(err) {
		t.Errorf("orphan staging dir should have been removed, stat err=%v", err)
	}
	if _, err := os.Stat(aliveDir); err != nil {
		t.Errorf("live-PID staging dir should have survived, stat err=%v", err)
	}
}

func formatOwn(pid int) string {
	return formatInt(pid) + "-1"
}

func formatInt(n int) string {
	return (func() string {
		buf := [20]byte{}
		i := len(buf)
		if n == 0 {
			return "0"
		}
		for n > 0 {
			i--
			buf[i] = byte('0' + n%10)
			n /= 10
		}
		return string(buf[i:])
	})()
}
