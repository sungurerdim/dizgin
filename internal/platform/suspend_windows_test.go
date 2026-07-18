// SPDX-License-Identifier: MIT

//go:build windows

package platform

import (
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// waitProcessReady polls until the process has at least one thread, indicating
// it has initialised enough to be suspendable. Falls back after a deadline.
func waitProcessReady(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
		if err == nil {
			_ = windows.CloseHandle(h)
			return
		}
		select {
		case <-t.Context().Done():
			t.Fatal("test cancelled while waiting for process to become ready")
		case <-time.After(5 * time.Millisecond):
		}
	}
	t.Fatalf("process %d did not become ready within deadline", pid)
}

func TestSuspendResumeProcess_Windows(t *testing.T) {
	// Start a short-lived background process.
	cmd := exec.Command("cmd.exe", "/c", "ping", "-n", "10", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start test process: %v", err)
	}
	pid := cmd.Process.Pid
	defer cmd.Process.Kill() //nolint:errcheck

	// Wait for the process to initialise rather than using a fixed sleep.
	waitProcessReady(t, pid)

	// Suspend should succeed.
	if err := SuspendProcess(pid); err != nil {
		t.Errorf("SuspendProcess(%d): %v", pid, err)
	}

	// Resume should succeed.
	if err := ResumeProcess(pid); err != nil {
		t.Errorf("ResumeProcess(%d): %v", pid, err)
	}

	// Clean up.
	cmd.Process.Kill() //nolint:errcheck
}

func TestSuspendProcess_NonExistent(t *testing.T) {
	// PID 999999999 very unlikely to exist.
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

func TestSuspendResume_DoubleSuspend(t *testing.T) {
	cmd := exec.Command("cmd.exe", "/c", "ping", "-n", "10", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start test process: %v", err)
	}
	pid := cmd.Process.Pid
	defer cmd.Process.Kill() //nolint:errcheck

	waitProcessReady(t, pid)

	// Suspend twice should not error (NtSuspendProcess is idempotent).
	if err := SuspendProcess(pid); err != nil {
		t.Fatalf("first suspend: %v", err)
	}
	if err := SuspendProcess(pid); err != nil {
		t.Errorf("second suspend: %v", err)
	}

	// Resume once to restore the process.
	if err := ResumeProcess(pid); err != nil {
		t.Errorf("resume: %v", err)
	}
}
