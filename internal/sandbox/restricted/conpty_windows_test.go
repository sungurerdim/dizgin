// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/sandbox"
)

// TestConPTYGivesChildRealConsole is the regression test for the
// interactive-TTY gap: before ConPTY support, the restricted child's
// stdio were anonymous pipes, so isatty() was false inside the child
// and REPL tools (Claude Code's Bun runtime, etc.) dropped into their
// non-interactive "--print" branch.
//
// It drives a box directly with PTY=true (bypassing session.go's
// isTerminal gate so it runs from the pipe-based test harness) and
// asserts that PowerShell, spawned inside the pseudoconsole, reports
// [Console]::IsInputRedirected == False — i.e. the child sees a real
// console, not a pipe.
func TestConPTYGivesChildRealConsole(t *testing.T) {
	// No recorder side effects (no ~/.dizgin/permissions writes).
	t.Setenv(brand.Env("NO_AUTO_GRANT"), "1")

	psPath, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skipf("powershell.exe not on PATH: %v", err)
	}

	sid, err := CurrentUserSID()
	if err != nil {
		t.Fatalf("CurrentUserSID: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Construct the box directly so the test does not run the sensitive
	// DENY sweep against the real user profile (that is backend.Create's
	// job and is covered by acl_windows_test.go). Only the fields Start
	// touches are set.
	b := &box{
		ctx: ctx,
		opts: sandbox.CreateOpts{
			PTY:         true,
			InitialCols: 120,
			InitialRows: 30,
		},
		sessionID: "test-conpty",
		userSID:   sid,
		policies:  DefaultPolicies(),
		jobLimits: JobLimits{},
		usePTY:    true,
	}

	args := []string{
		"-NoProfile", "-NonInteractive", "-Command",
		"Write-Output ('REDIRECTED=' + [Console]::IsInputRedirected)",
	}
	if err := b.Start(ctx, psPath, args, os.Environ()); err != nil {
		t.Fatalf("box.Start (PTY): %v", err)
	}

	pty := b.PTY()
	if pty == nil {
		_, _ = b.Wait()
		_ = b.Cleanup()
		t.Fatal("PTY() returned nil in PTY mode — pseudoconsole was not attached")
	}

	// ReadAll unblocks at EOF, which the exit reaper produces by closing
	// the pseudoconsole once PowerShell exits (output is tiny, well under
	// the pipe buffer, so no concurrent drain is needed).
	out, _ := io.ReadAll(pty)
	code, waitErr := b.Wait()
	if cerr := b.Cleanup(); cerr != nil {
		t.Errorf("Cleanup: %v", cerr)
	}
	if waitErr != nil {
		t.Fatalf("box.Wait: %v", waitErr)
	}

	got := string(out)
	t.Logf("conpty output (exit=%d): %q", code, got)

	if !strings.Contains(got, "REDIRECTED=False") {
		t.Fatalf("expected child stdin to be a real console (REDIRECTED=False); "+
			"got output %q — pseudoconsole did not give the child a TTY", got)
	}
}
