// SPDX-License-Identifier: MIT

//go:build integration && !windows

package e2e

import (
	"os/exec"
	"strings"
	"testing"
)

// TestEchoUnix runs `dizgin echo hello` on Unix and verifies output.
func TestEchoUnix(t *testing.T) {
	bin := dizginBin(t)

	cmd := exec.Command(bin, "--no-pty", "echo", "hello-dizgin")
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dizgin failed: %v\noutput: %s", err, out)
	}
	if !strings.Contains(string(out), "hello-dizgin") {
		t.Errorf("expected 'hello-dizgin' in output, got: %s", out)
	}
}

// TestExitCodeUnix verifies exit code propagation on Unix via sh -c 'exit N'.
func TestExitCodeUnix(t *testing.T) {
	bin := dizginBin(t)

	cmd := exec.Command(bin, "--no-pty", "sh", "-c", "exit 42")
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
