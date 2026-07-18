// SPDX-License-Identifier: MIT

//go:build windows

package platform

import (
	"fmt"

	"golang.org/x/sys/windows"
)

var (
	modNtdllPlat      = windows.NewLazySystemDLL("ntdll.dll")
	procNtSuspendProc = modNtdllPlat.NewProc("NtSuspendProcess")
	procNtResumeProc  = modNtdllPlat.NewProc("NtResumeProcess")
)

// SuspendProcess suspends all threads of the process with the given PID via NtSuspendProcess.
func SuspendProcess(pid int) error {
	h, err := openProcess(pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h) //nolint:errcheck

	r, _, _ := procNtSuspendProc.Call(uintptr(h))
	if r != 0 {
		return fmt.Errorf("suspend: NtSuspendProcess(%d): NTSTATUS 0x%08X", pid, r)
	}
	return nil
}

// ResumeProcess resumes all threads of the process with the given PID via NtResumeProcess.
func ResumeProcess(pid int) error {
	h, err := openProcess(pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h) //nolint:errcheck

	r, _, _ := procNtResumeProc.Call(uintptr(h))
	if r != 0 {
		return fmt.Errorf("resume: NtResumeProcess(%d): NTSTATUS 0x%08X", pid, r)
	}
	return nil
}

func openProcess(pid int) (windows.Handle, error) {
	h, err := windows.OpenProcess(windows.PROCESS_SUSPEND_RESUME, false, uint32(pid))
	if err != nil {
		return 0, fmt.Errorf("platform: OpenProcess(%d): %w", pid, err)
	}
	return h, nil
}
