// SPDX-License-Identifier: MIT

//go:build !windows

package platform

import (
	"fmt"

	"golang.org/x/sys/unix"
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
// Uses golang.org/x/sys/unix's per-GOOS RLIMIT_* constants rather than
// hand-rolled numbers: the resource-limit array indices genuinely differ
// between Darwin and Linux (RLIMIT_AS is 5 on Darwin, 9 on Linux;
// RLIMIT_NPROC is 7 on Darwin, 6 on Linux — verified against x/sys'
// generated zerrors_{darwin,linux}_*.go). A single shared constant for
// both platforms silently picked the wrong resource on one of them: the
// previous hardcoded RLIMIT_AS=9 is out of range on Darwin (Setrlimit
// fails loudly with EINVAL, so the memory cap was silently never applied
// on macOS), while the previous hardcoded RLIMIT_NPROC=7 is Linux's
// RLIMIT_NOFILE — that one fails silently, capping open file descriptors
// instead of process count with no error at all.
//
// Non-fatal: errors are returned but callers should log and continue.
func ApplyRlimits(cfg RlimitConfig) error {
	var errs []string

	if cfg.MemoryMB > 0 {
		limit := uint64(cfg.MemoryMB) * 1024 * 1024
		if err := unix.Setrlimit(unix.RLIMIT_AS, &unix.Rlimit{
			Cur: limit,
			Max: limit,
		}); err != nil {
			errs = append(errs, fmt.Sprintf("RLIMIT_AS: %v", err))
		}
	}

	if cfg.MaxPIDs > 0 {
		limit := uint64(cfg.MaxPIDs)
		if err := unix.Setrlimit(unix.RLIMIT_NPROC, &unix.Rlimit{
			Cur: limit,
			Max: limit,
		}); err != nil {
			errs = append(errs, fmt.Sprintf("RLIMIT_NPROC: %v", err))
		}
	}

	if cfg.CPUSeconds > 0 {
		limit := uint64(cfg.CPUSeconds)
		if err := unix.Setrlimit(unix.RLIMIT_CPU, &unix.Rlimit{
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
