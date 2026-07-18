// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// stampProgressRenderer prints a single-line progress indicator to
// stderr while the stamp storm runs. Three render modes:
//
//   - Warm (TTY, total < warmSuppressThreshold): one-shot
//     brand.Name+": preparing sandbox..." line, cleared when the storm ends.
//     Avoids stamping-progress spam for the common 5-15 mount case.
//   - TTY cold (total ≥ threshold): \r-prefixed live counter
//     "[ stamping 23/52 (44%) ]" overwritten in place.
//   - Non-TTY: periodic "stamping N/M" plain lines so logs stay tidy.
//
// The TTY modes throttle internally so the underlying stamp callback
// (called per-job from a worker goroutine) does not stall the worker
// pool on stderr writes.
type stampProgressRenderer struct {
	mu          sync.Mutex
	w           io.Writer
	lastDraw    time.Time
	lastDone    int
	total       int
	tty         bool
	finished    bool
	throttle    time.Duration
	warmEmitted bool
}

// warmSuppressThreshold is the mount count below which the renderer
// switches to the one-line "preparing sandbox" message instead of the
// N/M progress counter. Tuned so a typical warm session (~5-15 mounts:
// workdir + scratch + config + tool + lib deps) stays silent past the
// first hint, while a cold storm (post-dizgind-setup first run with
// 30+ paths) still gets the live counter.
const warmSuppressThreshold = 20

const (
	stampProgressMinInterval = 200 * time.Millisecond
	stampProgressDoneClear   = "\r" + "                                                  " + "\r"
)

// newStampProgressRenderer wires a renderer matched to whether stderr
// is a real terminal. The throttle defaults to 200ms — short enough
// that a 75 s storm shows ~375 updates, long enough that fast hosts
// don't waste cycles on stderr writes.
func newStampProgressRenderer() *stampProgressRenderer {
	return &stampProgressRenderer{
		w:        os.Stderr,
		tty:      isStderrTTY(),
		throttle: stampProgressMinInterval,
	}
}

// onProgress is the callback handed to restricted.OnStampProgress.
// Throttles draws and skips the no-progress case (some workers report
// faster than the renderer ticks). Always renders the "done" case
// regardless of throttle so the final count lands in the log.
func (r *stampProgressRenderer) onProgress(done, total int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.total = total
	if done <= r.lastDone {
		return
	}
	now := time.Now()
	if !r.finished && done < total && now.Sub(r.lastDraw) < r.throttle {
		r.lastDone = done
		return
	}
	r.lastDone = done
	r.lastDraw = now
	r.draw(done, total)
}

func (r *stampProgressRenderer) draw(done, total int) {
	pct := 0
	if total > 0 {
		pct = (done * 100) / total
	}
	// Warm-path suppression: total below the threshold gets a single
	// "preparing sandbox" line on the first draw and a clear on the
	// final draw. The per-job counter only kicks in for cold storms.
	if r.tty && total > 0 && total < warmSuppressThreshold {
		if !r.warmEmitted {
			_, _ = fmt.Fprint(r.w, "\r"+brand.Name+": preparing sandbox...")
			r.warmEmitted = true
		}
		if done >= total {
			_, _ = fmt.Fprint(r.w, stampProgressDoneClear)
			r.finished = true
		}
		return
	}
	if r.tty {
		_, _ = fmt.Fprintf(r.w, "\r[ stamping %d/%d (%d%%) ]", done, total, pct)
		if done >= total {
			_, _ = fmt.Fprint(r.w, stampProgressDoneClear)
			r.finished = true
		}
	} else {
		_, _ = fmt.Fprintf(r.w, brand.Name+": stamping %d/%d (%d%%)\n", done, total, pct)
		if done >= total {
			r.finished = true
		}
	}
}

// installStampProgress wires the renderer into the appcontainer
// stamp_parallel hot path. Idempotent: subsequent calls replace the
// callback with a fresh renderer (one dizgin session = one renderer
// instance).
func installStampProgress() {
	r := newStampProgressRenderer()
	setStampProgressCallback(r.onProgress)
}
