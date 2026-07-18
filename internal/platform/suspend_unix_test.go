// SPDX-License-Identifier: MIT

//go:build !windows

package platform

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSuspendResumeProcess_Unix(t *testing.T) {
	cmd := exec.Command("sleep", "10")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start test process: %v", err)
	}
	pid := cmd.Process.Pid
	defer cmd.Process.Kill() //nolint:errcheck

	// Wait for the child to reach a signal-deliverable state instead of
	// sleeping a fixed interval. `sleep` starts as running/sleeping
	// within a few ms; polling /proc avoids flake on slow CI while
	// cutting happy-path latency to the first tick.
	waitForProcessReady(t, pid)

	// Suspend should succeed (sends SIGSTOP).
	if err := SuspendProcess(pid); err != nil {
		t.Errorf("SuspendProcess(%d): %v", pid, err)
	}

	// On Linux, verify process state is "T" (traced/stopped).
	if runtime.GOOS == "linux" {
		state := readProcState(pid)
		if !strings.Contains(state, "T") {
			t.Errorf("expected state T (stopped) after SIGSTOP, got %q", state)
		}
	}

	// Resume should succeed (sends SIGCONT).
	if err := ResumeProcess(pid); err != nil {
		t.Errorf("ResumeProcess(%d): %v", pid, err)
	}

	cmd.Process.Kill() //nolint:errcheck
}

func TestSuspendProcess_NonExistent(t *testing.T) {
	err := SuspendProcess(999999999)
	if err == nil {
		t.Error("SuspendProcess on non-existent PID: expected error, got nil")
	}
}

func TestResumeProcess_NonExistent(t *testing.T) {
	err := ResumeProcess(999999999)
	if err == nil {
		t.Error("ResumeProcess on non-existent PID: expected error, got nil")
	}
}

// waitForProcessReady polls `kill(pid, 0)` until the kernel accepts a
// signal delivery for pid, replacing a fixed time.Sleep. The context
// from t.Context bounds the wait so CI never gets stuck if the child
// never reaches a ready state.
func waitForProcessReady(t *testing.T, pid int) {
	t.Helper()
	ctx := t.Context()
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.After(2 * time.Second)
	for {
		if err := syscall.Kill(pid, 0); err == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waitForProcessReady: %v", ctx.Err())
		case <-deadline:
			t.Fatalf("waitForProcessReady: pid %d never became signal-deliverable", pid)
		case <-ticker.C:
		}
	}
}

// readProcState reads the process state line from /proc/{pid}/status on Linux.
func readProcState(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "State:") {
			return line
		}
	}
	return ""
}
