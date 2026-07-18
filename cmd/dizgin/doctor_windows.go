// SPDX-License-Identifier: MIT

//go:build windows

package main

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sys/windows"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/sandbox"
)

// platformDoctorChecks runs the Windows-only restricted-backend smoke
// test — provision a Medium-IL restricted token, immediately close it.
// A failure here usually means the host's advapi32 surface is broken
// (extremely rare; indicates a corrupt Windows install).
func platformDoctorChecks() []doctorCheck {
	return []doctorCheck{
		checkRestrictedTokenSmoke(),
	}
}

// checkRestrictedTokenSmoke routes through the registered Backend's
// optional sandbox.SelfTester interface instead of importing
// internal/sandbox/restricted concretely, so doctor stays decoupled from
// the backend implementation (only the Backend/Box interface boundary).
func checkRestrictedTokenSmoke() doctorCheck {
	c := doctorCheck{Name: "restricted backend smoke"}
	backend, err := sandbox.Get(sandbox.BackendNameRestricted)
	if err != nil {
		c.Status = doctorFail
		c.Summary = fmt.Sprintf("backend %q not registered: %v", sandbox.BackendNameRestricted, err)
		c.Hint = "report a bug — the restricted backend should self-register via init()"
		return c
	}
	tester, ok := backend.(sandbox.SelfTester)
	if !ok {
		c.Status = doctorSkip
		c.Summary = "restricted backend does not implement SelfTest"
		return c
	}
	result := tester.SelfTest()
	c.Summary = result.Summary
	if result.OK {
		c.Status = doctorPass
	} else {
		c.Status = doctorFail
		c.Hint = result.Hint
	}
	return c
}

// pingDaemon dials the dizgind named pipe and immediately closes the
// handle. We only check addressability — a deeper protocol probe could
// hang if the daemon is half-initialised, which is the exact case
// doctor must NOT hide.
//
// 2 s timeout matches the dizgin main path's daemon-autostart wait.
func pingDaemon(ctx context.Context) error {
	const pipeName = brand.PipeName
	deadline := time.Now().Add(2 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	for {
		h, err := windows.CreateFile(
			windows.StringToUTF16Ptr(pipeName),
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0,
			nil,
			windows.OPEN_EXISTING,
			0,
			0,
		)
		if err == nil {
			_ = windows.CloseHandle(h)
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("could not open %s within 2s: %w", pipeName, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// freeBytesAt returns the number of free bytes available to the caller
// on the volume hosting path. Uses GetDiskFreeSpaceExW.
func freeBytesAt(path string) (uint64, error) {
	if path == "" {
		path = `C:\`
	}
	var freeAvail, totalBytes, totalFree uint64
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, fmt.Errorf("UTF16(%q): %w", path, err)
	}
	if err := windows.GetDiskFreeSpaceEx(p, &freeAvail, &totalBytes, &totalFree); err != nil {
		return 0, fmt.Errorf("GetDiskFreeSpaceEx(%q): %w", path, err)
	}
	return freeAvail, nil
}
