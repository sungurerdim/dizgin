// SPDX-License-Identifier: MIT

//go:build !windows

package platform

import (
	"fmt"
	"syscall"
)

// POSIX rlimit constants. Defined locally because syscall.RLIMIT_NPROC and
// syscall.RLIMIT_AS are not exported on all GOOS targets in Go's syscall package.
// Values are consistent across Linux and macOS.
const (
	rlimitCPU   = 0 // RLIMIT_CPU — same value on Linux and macOS
	rlimitAS    = 9 // RLIMIT_AS on Linux; on macOS RLIMIT_RSS (5) is the closest
	rlimitNPROC = 7 // RLIMIT_NPROC — same value on Linux and macOS
)

// RlimitConfig holds the resource limit parameters derived from config.
type RlimitConfig struct {
	MemoryMB   int // 0 = unlimited
	MaxPIDs    int // 0 = unlimited (RLIMIT_NPROC)
	CPUSeconds int // 0 = unlimited (RLIMIT_CPU)
}

// ApplyRlimits sets process resource limits for the current process.
// Call this in the child process before exec, or use SysProcAttr.Rlimit on Linux.
// On macOS/other Unix: limits are applied to the calling process and inherited
// by children. This must be called after fork but is here as a best-effort
// enforcement for seatbelt (which uses os/exec).
//
// Non-fatal: errors are returned but callers should log and continue.
func ApplyRlimits(cfg RlimitConfig) error {
	var errs []string

	if cfg.MemoryMB > 0 {
		limit := uint64(cfg.MemoryMB) * 1024 * 1024
		if err := syscall.Setrlimit(rlimitAS, &syscall.Rlimit{
			Cur: limit,
			Max: limit,
		}); err != nil {
			errs = append(errs, fmt.Sprintf("RLIMIT_AS: %v", err))
		}
	}

	if cfg.MaxPIDs > 0 {
		limit := uint64(cfg.MaxPIDs)
		if err := syscall.Setrlimit(rlimitNPROC, &syscall.Rlimit{
			Cur: limit,
			Max: limit,
		}); err != nil {
			errs = append(errs, fmt.Sprintf("RLIMIT_NPROC: %v", err))
		}
	}

	if cfg.CPUSeconds > 0 {
		limit := uint64(cfg.CPUSeconds)
		if err := syscall.Setrlimit(rlimitCPU, &syscall.Rlimit{
			Cur: limit,
			Max: limit,
		}); err != nil {
			errs = append(errs, fmt.Sprintf("RLIMIT_CPU: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("rlimit: %v", errs)
	}
	return nil
}
