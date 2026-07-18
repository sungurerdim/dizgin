// SPDX-License-Identifier: MIT

//go:build windows

package restricted

// TST-12 — runWithDeadline: success path, timeout path, goroutine safety.
//
// The internal log.DebugSub call on timeout is a no-op in test builds
// (it writes to an internal buffer) — no special wiring needed.

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestRunWithDeadline_FastFnReturnsTrue(t *testing.T) {
	called := make(chan struct{})
	ok := runWithDeadline("fast-op", 5*time.Second, func() {
		close(called)
	})
	if !ok {
		t.Error("fast fn completing before deadline should return true")
	}
	select {
	case <-called:
		// good — fn was executed
	case <-time.After(1 * time.Second):
		t.Error("fn was never called")
	}
}

func TestRunWithDeadline_TimeoutReturnsFalse(t *testing.T) {
	// A function that blocks until the test cancels it.
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	ok := runWithDeadline("slow-op", 50*time.Millisecond, func() {
		<-done // blocks until cleanup
	})
	if ok {
		t.Error("slow fn exceeding deadline should return false")
	}
}

func TestRunWithDeadline_FnResultIsObserved(t *testing.T) {
	// Verify the fn's side-effect is visible on the true path.
	var counter int64
	ok := runWithDeadline("counter-op", 5*time.Second, func() {
		atomic.AddInt64(&counter, 1)
	})
	if !ok {
		t.Error("expected true (fast fn)")
	}
	if atomic.LoadInt64(&counter) != 1 {
		t.Errorf("fn side-effect not observed: counter = %d", atomic.LoadInt64(&counter))
	}
}

func TestRunWithDeadline_ZeroDurationTimeoutImmediately(t *testing.T) {
	// A zero deadline should essentially always time out; fn may or may not
	// run. We only assert no panic and that bool is returned.
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	// Give fn 0 deadline — goroutine races to completion.
	// Either true or false is acceptable; what is NOT acceptable is a hang
	// or panic.
	result := make(chan bool, 1)
	go func() {
		result <- runWithDeadline("zero-deadline", 0, func() { <-done })
	}()
	select {
	case r := <-result:
		_ = r // both values are valid given the race
	case <-time.After(2 * time.Second):
		t.Error("runWithDeadline with zero deadline hung for 2s — unexpected")
	}
}

func TestRunWithDeadline_MultipleCallsSerially(t *testing.T) {
	// Ensure repeated calls work correctly with no state leak between them.
	for i := 0; i < 5; i++ {
		ok := runWithDeadline("serial-op", 2*time.Second, func() {
			time.Sleep(1 * time.Millisecond)
		})
		if !ok {
			t.Errorf("call %d: expected true for a 1ms fn with 2s deadline", i)
		}
	}
}

func TestRunWithDeadline_TimeoutDoesNotBlockCaller(t *testing.T) {
	// The caller must return promptly after the deadline — not wait for fn.
	start := time.Now()
	const budget = 100 * time.Millisecond

	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	ok := runWithDeadline("blocking-op", budget, func() { <-done })

	elapsed := time.Since(start)
	if ok {
		t.Error("expected false (deadline exceeded)")
	}
	// Allow 2× budget for scheduling jitter on a loaded CI host.
	if elapsed > 2*budget+200*time.Millisecond {
		t.Errorf("runWithDeadline blocked caller for %v beyond the %v deadline", elapsed, budget)
	}
}
