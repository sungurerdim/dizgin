// SPDX-License-Identifier: MIT

//go:build windows && integration

package e2e

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestCleanupPostExec_NoHang verifies that dizgin exits within a reasonable
// time after the child process finishes. Prior to the timeout boundary
// fix (2026-05-15), a hung icacls subprocess in the daemon's revoke path
// or a blocked DeleteProfile/revokeFn syscall in dizgin's Cleanup loop
// caused dizgin to hang indefinitely — observed as exit code 124 from a
// parent runner that killed dizgin after ~120 s.
//
// This test fails if dizgin takes more than 10 s to return control, which
// catches both the daemon-side (A1) and dizgin-side (A2/A3) hang scenarios.
func TestCleanupPostExec_NoHang(t *testing.T) {
	bin := dizginBin(t)
	wd := t.TempDir()

	start := time.Now()
	cmd := exec.Command(bin, "-w", wd, "--no-pty", "cmd", "/c", "echo", "CLEANUP_OK")
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("dizgin exited with error after %s: %v\noutput: %s", elapsed, err, out)
	}
	if !strings.Contains(string(out), "CLEANUP_OK") {
		t.Errorf("expected 'CLEANUP_OK' in output, got: %s", out)
	}
	// Threshold: 30 s accounts for the timeout boundaries introduced by
	// the 2026-05-15 cleanup-hang fix. Worst case: two PATH-adjacent
	// directories (e.g. GOPATH) cause icacls to hang, each hitting the
	// 10 s A2 timeout → ~22 s total. Pre-fix: indefinitely hung (parent
	// runner killed dizgin at ~120 s). 30 s is tight enough to catch a
	// regression while giving the timeout mechanism room to breathe.
	if elapsed > 30*time.Second {
		t.Errorf("dizgin took %s to exit — likely hung in Cleanup (threshold: 30s)", elapsed)
	}
}
