// SPDX-License-Identifier: MIT

//go:build integration

package e2e

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestHostPathEqualsGuestPath asserts the R2 (Native Experience)
// invariant: a path passed to dizgin as the workdir is the SAME path
// the sandboxed process sees. No path translation, no virtual home,
// no chroot. This is the regression catcher for any future change
// that accidentally introduces a staging layer.
//
// Phase 1 plan, item E1.
//
// Per backend the probe command is the platform's native "print
// current working directory" — no shell-specific quoting that could
// get rewritten by MSYS or by dizgin's argv pipeline.
func TestHostPathEqualsGuestPath(t *testing.T) {
	bin := dizginBin(t)

	// Use t.TempDir() but resolve symlinks (macOS /var → /private/var)
	// so the comparison runs against the path the kernel actually
	// reports, not the OS-level alias.
	rawWd := t.TempDir()
	wd, err := filepath.EvalSymlinks(rawWd)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", rawWd, err)
	}

	var pwdCmd string
	var pwdArgs []string
	switch runtime.GOOS {
	case "windows":
		pwdCmd = "cmd"
		pwdArgs = []string{"/c", "cd"}
	default:
		pwdCmd = "pwd"
		pwdArgs = []string{}
	}

	args := append([]string{"--no-pty", "-w", wd, pwdCmd}, pwdArgs...)
	cmd := exec.Command(bin, args...)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	if runErr := cmd.Run(); runErr != nil {
		t.Fatalf("dizgin %v: %v\nstdout:\n%s\nstderr:\n%s", args, runErr, stdoutBuf.String(), stderrBuf.String())
	}

	got := strings.TrimSpace(stdoutBuf.String())
	// Resolve symlinks on the reported path too, so a dizgin that emits
	// the canonical form is not mis-flagged when wd is the alias
	// (or vice versa).
	gotResolved, err := filepath.EvalSymlinks(got)
	if err != nil {
		// If the path doesn't exist (some printf shells append junk),
		// fall back to the raw comparison and let the assertion fail
		// loudly with the real value.
		gotResolved = got
	}

	wantLower := strings.ToLower(filepath.Clean(wd))
	gotLower := strings.ToLower(filepath.Clean(gotResolved))
	if wantLower != gotLower {
		t.Fatalf("host_path != guest_path:\n  host:  %s\n  guest: %s\n  raw output: %q",
			wantLower, gotLower, stdoutBuf.String())
	}
}

// TestHostPathEqualsGuestPath_NoTranslation asserts that even when
// the workdir contains characters MSYS conversion would mangle
// (drive-letter root, mixed slashes), dizgin's reported path matches
// the host invocation byte-for-byte after Clean. Catches regressions
// where a future "helpful" path normaliser slips in.
func TestHostPathEqualsGuestPath_NoTranslation(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("drive-letter normalisation is Windows-only")
	}

	bin := dizginBin(t)
	wd := t.TempDir()

	// Inject a deliberately mixed-separator workdir to flush out any
	// path normaliser that would silently translate. dizgin normalises
	// via filepath.Clean which preserves drive letters.
	mixed := strings.ReplaceAll(wd, "\\", "/")

	args := []string{"--no-pty", "-w", mixed, "cmd", "/c", "cd"}
	cmd := exec.Command(bin, args...)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	if err := cmd.Run(); err != nil {
		t.Fatalf("dizgin with mixed-separator workdir failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdoutBuf.String(), stderrBuf.String())
	}
	got := strings.TrimSpace(stdoutBuf.String())
	gotClean := strings.ToLower(filepath.Clean(got))
	wantClean := strings.ToLower(filepath.Clean(wd))
	if wantClean != gotClean {
		t.Fatalf("mixed-separator workdir not preserved:\n  want: %s\n  got:  %s", wantClean, gotClean)
	}
}
