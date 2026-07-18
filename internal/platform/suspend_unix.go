// SPDX-License-Identifier: MIT

//go:build !windows

package platform

import (
	"fmt"
	"os"
	"syscall"
)

// SuspendProcess sends SIGSTOP to the process with the given PID.
func SuspendProcess(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("suspend: find process %d: %w", pid, err)
	}
	if err = proc.Signal(syscall.SIGSTOP); err != nil {
		return fmt.Errorf("suspend: SIGSTOP(%d): %w", pid, err)
	}
	return nil
}

// ResumeProcess sends SIGCONT to the process with the given PID.
func ResumeProcess(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("resume: find process %d: %w", pid, err)
	}
	if err = proc.Signal(syscall.SIGCONT); err != nil {
		return fmt.Errorf("resume: SIGCONT(%d): %w", pid, err)
	}
	return nil
}
