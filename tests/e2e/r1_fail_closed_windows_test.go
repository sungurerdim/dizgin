// SPDX-License-Identifier: MIT

//go:build windows && integration

// Package e2e: R1 (Full FS Isolation) regression test. iter6's
// restricted backend runs the child as the same user with Medium IL
// + a Job Object + DACL DENYs on the sensitive SSOT, and trusts the
// user's natural NTFS permissions to keep system paths read-only.
// This test asserts the contract directly: a sandboxed process must
// not be able to write under C:\Windows\Temp from inside the box.
package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestR1FailClosed asserts that a sandboxed `powershell -c` process
// cannot write outside its workdir under C:\Windows. The restricted
// token's Medium IL + the user's natural NTFS perms on system paths
// combine to deny the write; this test catches a regression where
// either layer slips.
//
// Skips if the dizgin binary isn't available; CI builds the binary
// before invoking this suite.
func TestR1FailClosed(t *testing.T) {
	bin := dizginBin(t)

	if _, err := exec.LookPath("powershell"); err != nil {
		t.Skip("powershell not on PATH — skipping R1 fail-closed test")
	}

	wd := t.TempDir()
	target := `C:\Windows\Temp\dizgin-r1-leak-` + filepath.Base(t.TempDir()) + ".txt"

	// Pre-clean: make sure no stale target file from a previous run
	// makes the assertion pass spuriously.
	_ = os.Remove(target)

	// Attempt the forbidden write. We use Set-Content rather than `>`
	// redirection so PowerShell surfaces an explicit AccessDenied
	// exception rather than a shell-level error code.
	psScript := `Set-Content -Path '` + target + `' -Value 'fail' -ErrorAction Stop`
	cmd := exec.Command(bin, "-w", wd, "--no-pty", "--", "powershell", "-NoProfile", "-Command", psScript)
	cmd.Dir = wd
	out, runErr := cmd.CombinedOutput()

	// R1 contract: the write MUST be denied. Either the powershell
	// process exits non-zero (preferred) or the file exists (failure).
	// We accept either signal — an exit-zero with a created file would
	// be the only true regression.
	if _, statErr := os.Stat(target); statErr == nil {
		_ = os.Remove(target)
		t.Fatalf("R1 REGRESSION: sandboxed powershell wrote %s — non-inheriting ALL APP PKG grant must not propagate to C:\\Windows\\Temp\nrunErr: %v\noutput: %s",
			target, runErr, out)
	}

	// Belt-and-braces: with the file absent, runErr should be non-nil
	// (PowerShell's Set-Content -ErrorAction Stop surfaces a non-zero
	// exit). If runErr is nil despite the file being absent, that's a
	// dramatic shell quirk worth surfacing in the test log but not a
	// hard failure — the file-absent invariant is the source of truth.
	if runErr == nil {
		t.Logf("note: powershell exited zero but target file absent (dizgin output: %s)", out)
	}

	// The combined output should look like an access denial. Accept
	// both English ("Access to the path") and a generic FullyQualified
	// ErrorId hint ("UnauthorizedAccess") so localized hosts don't
	// false-negative.
	lower := strings.ToLower(string(out))
	hints := []string{"access", "denied", "unauthorized", "permission", "erişim", "izin"}
	matched := false
	for _, h := range hints {
		if strings.Contains(lower, h) {
			matched = true
			break
		}
	}
	if !matched {
		t.Logf("note: no recognized access-denied hint in dizgin output — locale or shell may have suppressed the message: %s", out)
	}
}
