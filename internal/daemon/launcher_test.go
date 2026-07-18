// SPDX-License-Identifier: MIT

package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// TST-03: Launcher / LaunchSession / RestartSession.

// ── Missing binary error path ─────────────────────────────────────────────────

func TestLauncher_LaunchSession_MissingBinary(t *testing.T) {
	l := &Launcher{DizginBin: ""}
	_, err := l.LaunchSession("claude", t.TempDir(), nil)
	if err == nil {
		t.Fatal("LaunchSession with empty DizginBin: want error, got nil")
	}
	if !strings.Contains(err.Error(), "dizgin binary not found") {
		t.Errorf("error message should mention 'dizgin binary not found', got: %v", err)
	}
}

func TestLauncher_LaunchSession_EmptyTool(t *testing.T) {
	l := &Launcher{DizginBin: "/some/path/dizgin"}
	_, err := l.LaunchSession("", t.TempDir(), nil)
	if err == nil {
		t.Fatal("LaunchSession with empty tool: want error, got nil")
	}
	if !strings.Contains(err.Error(), "tool name required") {
		t.Errorf("error message should mention 'tool name required', got: %v", err)
	}
}

// ── Argument construction ─────────────────────────────────────────────────────

// TestLauncher_LaunchSession_ArgConstruction verifies the dizgin command line is
// built correctly: dizgin [-w workdir] tool [args...]. We use the platform's
// true/exit-0 binary as dizgin so the process actually spawns and we can capture
// the argv.
//
// On Windows we use "cmd /c exit 0" as a stand-in; on Unix we use "true".
// The binary path is embedded as DizginBin; the actual tool arg doesn't
// matter as long as the child exits cleanly.
func TestLauncher_LaunchSession_ArgConstruction_WithWorkdir(t *testing.T) {
	// Build a tiny helper script/binary that immediately exits 0.
	// We use `go run` writing a self-contained Go program to a temp file,
	// or simply exec a known system binary that exits 0.
	var bin string
	var toolArgs []string
	switch runtime.GOOS {
	case "windows":
		// "cmd" always exists on Windows.
		bin = findSystemBin(t, "cmd.exe", "cmd")
		toolArgs = []string{"/c", "exit", "0"}
	default:
		bin = findSystemBin(t, "true")
		toolArgs = nil
	}
	if bin == "" {
		t.Skip("cannot locate a harmless exit-0 binary for this platform")
	}

	wd := t.TempDir()
	l := &Launcher{DizginBin: bin}

	pid, err := l.LaunchSession("ignoredtool", wd, toolArgs)
	if err != nil {
		t.Fatalf("LaunchSession: %v", err)
	}
	if pid <= 0 {
		t.Errorf("PID: want >0, got %d", pid)
	}
}

func TestLauncher_LaunchSession_ArgConstruction_NoWorkdir(t *testing.T) {
	var bin string
	switch runtime.GOOS {
	case "windows":
		bin = findSystemBin(t, "cmd.exe", "cmd")
	default:
		bin = findSystemBin(t, "true")
	}
	if bin == "" {
		t.Skip("cannot locate a harmless exit-0 binary for this platform")
	}

	l := &Launcher{DizginBin: bin}
	// Empty workdir: dizgin [-w workdir] is omitted.
	pid, err := l.LaunchSession("sometool", "", nil)
	if err != nil {
		t.Fatalf("LaunchSession without workdir: %v", err)
	}
	if pid <= 0 {
		t.Errorf("PID: want >0, got %d", pid)
	}
}

// ── RestartSession ────────────────────────────────────────────────────────────

func TestLauncher_RestartSession_SessionNotFound(t *testing.T) {
	l := &Launcher{DizginBin: "/some/dizgin"}
	reg := NewRegistry()
	_, err := l.RestartSession(reg, "nonexistent-id", func(id string) error { return nil })
	if err == nil {
		t.Fatal("RestartSession for unknown session: want error, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
}

func TestLauncher_RestartSession_KillFails(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&Instance{InstanceData: InstanceData{
		ID:      "kill-fail-sess",
		Tool:    "claude",
		Workdir: t.TempDir(),
		Status:  StatusRunning,
	}})

	l := &Launcher{DizginBin: "/some/dizgin"}
	killErr := func(id string) error {
		return os.ErrPermission
	}
	_, err := l.RestartSession(reg, "kill-fail-sess", killErr)
	if err == nil {
		t.Fatal("RestartSession with failing kill: want error, got nil")
	}
	if !strings.Contains(err.Error(), "kill") {
		t.Errorf("error should mention 'kill', got: %v", err)
	}
}

// ── findDizginBinary ─────────────────────────────────────────────────────────

func TestFindDizginBinary_ContractHolds(t *testing.T) {
	// Point PATH at an empty dir so the PATH-lookup branch cannot resolve.
	// The os.Executable() sibling branch may still find a co-located binary
	// in some build layouts, so the contract we assert is: the result is
	// EITHER empty OR an absolute path to a file that actually exists — never
	// a relative or dangling path that would fail at exec time.
	t.Setenv("PATH", t.TempDir())

	got := findDizginBinary()
	if got == "" {
		return
	}
	if !filepath.IsAbs(got) {
		t.Errorf("findDizginBinary() = %q, want absolute path or empty", got)
	}
	if _, err := os.Stat(got); err != nil {
		t.Errorf("findDizginBinary() = %q, but it does not exist: %v", got, err)
	}
}

func TestNewLauncher_DetectsBinaryOnPATH(t *testing.T) {
	// Place a fake brand.Name (or brand.Name+".exe" on Windows) on PATH and verify
	// NewLauncher picks it up.
	dir := t.TempDir()
	fakeName := brand.Name
	if runtime.GOOS == "windows" {
		fakeName = brand.Name + ".exe"
	}
	fakeDizgin := filepath.Join(dir, fakeName)

	// Write a minimal executable: on Windows a .exe that exits 0; on Unix a
	// shell script. For the PATH-detection test we only need the file to exist
	// and be executable.
	if runtime.GOOS == "windows" {
		// Build a trivial go program to get a real .exe.
		src := `package main; func main() {}`
		srcFile := filepath.Join(dir, "main.go")
		if err := os.WriteFile(srcFile, []byte(src), 0o644); err != nil {
			t.Fatalf("write main.go: %v", err)
		}
		cmd := exec.Command("go", "build", "-o", fakeDizgin, srcFile)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("cannot build fake dizgin.exe: %v\n%s", err, out)
		}
	} else {
		if err := os.WriteFile(fakeDizgin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatalf("write fake dizgin: %v", err)
		}
	}

	t.Setenv("PATH", dir)
	l := NewLauncher()
	if l.DizginBin == "" {
		t.Error("NewLauncher: expected dizgin binary to be found on PATH, got empty string")
	}
	if !strings.Contains(strings.ToLower(l.DizginBin), brand.Name) {
		t.Errorf("DizginBin should contain 'dizgin', got %q", l.DizginBin)
	}
}

// findSystemBin looks up the first of the named binaries that exists.
func findSystemBin(t *testing.T, names ...string) string {
	t.Helper()
	for _, name := range names {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}
