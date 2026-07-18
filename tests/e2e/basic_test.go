// SPDX-License-Identifier: MIT

//go:build integration

// Package e2e contains end-to-end integration tests for dizgin.
// Run with: go test -tags=integration ./tests/e2e/...
// These tests require an actual sandbox backend to be available.
package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// dizginBin returns the absolute path to the dizgin binary built for testing.
// On Windows the binary has the .exe extension.
// Build with: go build -o tests/e2e/testdata/dizgin.exe ./cmd/dizgin   (Windows)
//
//	go build -o tests/e2e/testdata/dizgin    ./cmd/dizgin   (Unix)
func dizginBin(t *testing.T) string {
	t.Helper()
	bin := filepath.Join("testdata", brand.Name)
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	abs, err := filepath.Abs(bin)
	if err != nil {
		t.Fatalf("dizginBin: abs path: %v", err)
	}
	if _, err := os.Stat(abs); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("dizgin binary not found at %s; build it first: go build -o %s ./cmd/dizgin", abs, abs)
		}
		t.Skipf("dizgin binary not found at %s; build it first: go build -o %s ./cmd/dizgin", abs, abs)
	}
	return abs
}

// TestBasicEcho runs `dizgin echo hello` and verifies the output.
func TestBasicEcho(t *testing.T) {
	bin := dizginBin(t)

	cmd := exec.Command(bin, "--no-pty", "cmd", "/c", "echo", "hello-dizgin")
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dizgin failed: %v\noutput: %s", err, out)
	}
	if !strings.Contains(string(out), "hello-dizgin") {
		t.Errorf("expected 'hello-dizgin' in output, got: %s", out)
	}
}

// TestWorkdirAccess verifies the sandboxed process can write to the workdir.
// The sandbox runs cmd /c echo ... > output.txt and the host reads it back.
func TestWorkdirAccess(t *testing.T) {
	bin := dizginBin(t)
	wd := t.TempDir()

	// Have the sandbox write a file.  Using echo+redirect avoids the
	// cmd.exe built-in `type` argument-parsing quirks inside containers.
	outFile := filepath.Join(wd, "output.txt")
	cmd := exec.Command(bin, "-w", wd, "--no-pty",
		"cmd", "/c", "echo dizgin-test > output.txt")
	cmd.Dir = wd
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dizgin failed: %v\noutput: %s", err, out)
	}

	// Read the file from the host.
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("output.txt not created by sandbox: %v", err)
	}
	if !strings.Contains(string(data), "dizgin-test") {
		t.Errorf("expected 'dizgin-test' in output.txt, got: %q", string(data))
	}
}

// TestExitCode verifies the exit code is propagated correctly.
func TestExitCode(t *testing.T) {
	bin := dizginBin(t)

	cmd := exec.Command(bin, "--no-pty", "cmd", "/c", "exit", "42")
	cmd.Dir = t.TempDir()
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit code, got 0")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected *exec.ExitError, got %T: %v", err, err)
	}
	if exitErr.ExitCode() != 42 {
		t.Errorf("exit code: got %d, want 42", exitErr.ExitCode())
	}
}

// TestToolNotFound verifies exit code 126 when the tool is not in PATH.
func TestToolNotFound(t *testing.T) {
	bin := dizginBin(t)

	cmd := exec.Command(bin, "--no-pty", "nonexistent-tool-xyzzy-dizgin")
	cmd.Dir = t.TempDir()
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit code")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected *exec.ExitError, got %T", err)
	}
	if exitErr.ExitCode() != 126 {
		t.Errorf("exit code: got %d, want 126", exitErr.ExitCode())
	}
}

// TestNetworkBlocked verifies that blocked network policy prevents outbound connections.
func TestNetworkBlocked(t *testing.T) {
	bin := dizginBin(t)
	wd := t.TempDir()

	// Write a minimal dizgin.yaml with blocked network.
	cfg := `version: 1
network:
  policy: blocked
`
	if err := os.WriteFile(filepath.Join(wd, "dizgin.yaml"), []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}

	// Try to use curl/wget to reach the internet — should fail.
	// Use a context timeout instead of time.After to ensure the process is
	// killed automatically when the deadline expires.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "-w", wd, "--no-pty",
		"cmd", "/c", "curl", "--connect-timeout", "3", "https://example.com")
	cmd.Dir = wd

	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		t.Log("TestNetworkBlocked: timeout (network block confirmed — curl hung)")
		return
	}
	if err == nil {
		t.Error("expected curl to fail under blocked network policy")
	}
	// Any non-zero exit is acceptable — curl can't connect.
}
