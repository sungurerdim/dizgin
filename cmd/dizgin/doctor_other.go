// SPDX-License-Identifier: MIT

//go:build !windows

package main

import (
	"context"
	"fmt"
	"syscall"
)

// platformDoctorChecks returns the platform-specific check list. The
// macOS / Linux build has no restricted backend probe; this stub keeps the
// signature stable so the doctor entry point compiles on every OS.
func platformDoctorChecks() []doctorCheck {
	return []doctorCheck{
		{
			Name:    "restricted backend smoke",
			Status:  doctorSkip,
			Summary: "Restricted backend smoke test is Windows-only",
		},
	}
}

// pingDaemon attempts a minimal availability probe of the dizgind
// IPC endpoint. Unix builds use SO_PEERCRED-protected sockets at
// %XDG_RUNTIME_DIR%/dizgind.sock or /tmp/dizgind.sock; we only need
// to confirm that one of those paths is connectable.
//
// Returns nil on first successful connect, error otherwise.
func pingDaemon(ctx context.Context) error {
	// Stub: defer a real probe to a follow-up PR that wires the unix
	// socket dial. The doctor surface still flags absence loudly with
	// the dummy implementation below — replace when daemon/client.go
	// exposes a public Ping helper for non-Windows.
	_ = ctx
	return fmt.Errorf("daemon ping not yet implemented for this platform")
}

// freeBytesAt returns the number of free bytes on the filesystem
// containing path. Uses Statfs on Unix.
func freeBytesAt(path string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}
