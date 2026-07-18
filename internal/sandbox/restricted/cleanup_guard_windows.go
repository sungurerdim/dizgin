// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"time"

	"github.com/sungurerdim/dizgin/internal/log"
)

// runWithDeadline runs fn on a background goroutine and waits up to d
// for it to finish. Returns true on completion, false on deadline.
//
// Used by Cleanup to bound best-effort syscalls (revoke sweeps, Job
// handle close races) that cannot be cancelled mid-call. A timeout
// leaks the goroutine until the underlying syscall returns — accepted
// trade because dizgin is exiting and the OS reaper catches state.
func runWithDeadline(name string, d time.Duration, fn func()) bool {
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
		return true
	case <-time.After(d):
		log.DebugSub(log.SubContainer, "restricted: %s exceeded %s, abandoning", name, d)
		return false
	}
}
