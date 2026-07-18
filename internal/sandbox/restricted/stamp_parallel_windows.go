// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"context"
	"runtime"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// stampParallelismCap caps concurrent stamp workers. NTFS metadata
// throughput saturates well before 16; 8 is the same point appcontainer
// landed on after benchmarking. The native SetNamedSecurityInfo path
// is cheap (~5-20 ms per call) so a 15-path DENY sweep on a typical
// session completes in well under 100 ms even on cold cache.
const stampParallelismCap = 8

func stampParallelism(n int) int {
	if n <= 0 {
		return 1
	}
	w := runtime.NumCPU()
	if w > stampParallelismCap {
		w = stampParallelismCap
	}
	if w > n {
		w = n
	}
	return w
}

// stampJob is one path that needs a DACL ACE applied. mode selects
// between grant and deny so a single worker pool can drive both the
// sensitive-DENY sweep and the (rare) foreign-volume GRANT sweep
// without separate orchestration code.
type stampJob struct {
	path     string
	mode     stampMode
	readOnly bool
}

// OnStampProgress is the optional progress reporter called after every
// stamp job completes. Wired by cmd/dizgin at startup; nil in production
// builds without a renderer attached. Mirrors the appcontainer hook so
// the same StampProgress UI layer survives the backend swap.
var OnStampProgress func(done, total int)

// revokeStampsDeadline caps the cleanup-time revoke sweep. Cleanup runs
// during dizgin's exit path; a hung icacls call would stall the parent
// shell. 3 s matches the appcontainer constant — empirically enough
// for 30+ paths against an SSD even on a cold cache.
const revokeStampsDeadline = 3 * time.Second

// revokeStampsParallel removes every ACE for trustee from each path in
// the input list, in parallel, bounded by revokeStampsDeadline. A
// timeout cancels the outer context; native SetNamedSecurityInfo is
// already non-blocking from dizgin's perspective so the deadline only
// trims overall wall-clock on pathological NTFS journal commits.
func revokeStampsParallel(paths []string, trustee *windows.SID) {
	if len(paths) == 0 || trustee == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), revokeStampsDeadline)
	defer cancel()

	workers := stampParallelism(len(paths))
	ch := make(chan string, len(paths))
	done := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range ch {
				if ctx.Err() != nil {
					return
				}
				_ = RevokePathForTrusteeCtx(ctx, p, trustee)
			}
		}()
	}
	for _, p := range paths {
		ch <- p
	}
	close(ch)
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		<-done
	}
}

// stampJobsParallel runs StampPathGrant / StampPathDeny concurrently
// across a worker pool. Returns successfully-stamped paths (caller
// rolls back on failure), the first error's path, and the first error.
//
// Result aggregation drains a buffered channel so workers never block
// after their job completes — even if the caller is slow to consume.
// The pool is small enough that we collect every result before
// returning rather than short-circuiting on the first error; this
// simplifies rollback and the wasted work is negligible at the cap.
func stampJobsParallel(jobs []stampJob, trustee *windows.SID) (
	completed []string, firstErrPath string, firstErr error,
) {
	if len(jobs) == 0 {
		return nil, "", nil
	}

	type stampResult struct {
		path string
		err  error
	}

	workers := stampParallelism(len(jobs))
	jobsCh := make(chan stampJob, len(jobs))
	resultsCh := make(chan stampResult, len(jobs))

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobsCh {
				var err error
				switch j.mode {
				case stampModeDeny:
					err = StampPathDeny(j.path, trustee)
				default:
					err = StampPathGrant(j.path, trustee, j.readOnly)
				}
				resultsCh <- stampResult{path: j.path, err: err}
			}
		}()
	}

	for _, j := range jobs {
		jobsCh <- j
	}
	close(jobsCh)
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	completed = make([]string, 0, len(jobs))
	done := 0
	total := len(jobs)
	for r := range resultsCh {
		done++
		if cb := OnStampProgress; cb != nil {
			cb(done, total)
		}
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
				firstErrPath = r.path
			}
			continue
		}
		completed = append(completed, r.path)
	}
	return completed, firstErrPath, firstErr
}
