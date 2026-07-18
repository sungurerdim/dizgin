// SPDX-License-Identifier: MIT

//go:build windows

package platform

import "github.com/sungurerdim/dizgin/internal/log"

// RlimitConfig holds the resource limit parameters derived from config.
// On Windows, resource limits are enforced via Job Objects (see
// sandbox/container), not POSIX rlimits. This stub exists for
// interface symmetry with the Unix implementation.
type RlimitConfig struct {
	MemoryMB   int // 0 = unlimited
	MaxPIDs    int // 0 = unlimited
	CPUSeconds int // 0 = unlimited
}

// ApplyRlimits is a no-op on Windows. Resource limits are enforced via
// Job Objects in the restricted backend. Note that cpu_percent from the
// profile is silently ignored: Windows Job Objects do not expose a CPU-share
// cap equivalent, so only MemoryMB and MaxPIDs are enforced.
func ApplyRlimits(cfg RlimitConfig) error {
	if cfg.CPUSeconds > 0 {
		log.Warn("rlimit: cpu_percent is not enforced on Windows — Job Objects do not expose a CPU-share cap")
	}
	return nil
}
