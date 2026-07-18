// SPDX-License-Identifier: MIT

//go:build windows && integration

package e2e

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNoPtyStdio_OutputCaptured verifies that dizgin --no-pty correctly
// forwards the child's stdout to the caller. This is the regression
// guard for R2-01 (AppContainer child stdio inheritance fix, 2026-05-06):
// the child runs at Low IL, so inherited host stdout handles were
// silently dropped. Option B (owned anonymous pipe pairs with AC SID
// granted on creation) fixed the data path; this test ensures it stays
// fixed.
//
// The test is the first to exercise the --no-pty code path end-to-end;
// TestBasicEcho in basic_test.go exercises the default (PTY) path.
func TestNoPtyStdio_OutputCaptured(t *testing.T) {
	bin := dizginBin(t)
	wd := t.TempDir()

	cmd := exec.Command(bin, "-w", wd, "--no-pty", "cmd", "/c", "echo", "NO_PTY_OK")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dizgin --no-pty failed: %v\noutput: %s", err, out)
	}
	got := strings.TrimSpace(string(out))
	if !strings.Contains(got, "NO_PTY_OK") {
		t.Errorf("expected 'NO_PTY_OK' in output, got: %q", got)
	}
}
