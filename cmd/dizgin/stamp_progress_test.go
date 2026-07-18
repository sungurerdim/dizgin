// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func newTestRenderer(tty bool) (*stampProgressRenderer, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	r := &stampProgressRenderer{
		w:        buf,
		tty:      tty,
		throttle: time.Millisecond, // tight in tests so throttle does not hide draws
	}
	return r, buf
}

func TestStampProgress_NonTTY_PlainTextLines(t *testing.T) {
	r, buf := newTestRenderer(false)
	r.onProgress(1, 3)
	r.mu.Lock()
	r.lastDraw = time.Time{}
	r.mu.Unlock()
	r.onProgress(2, 3)
	r.mu.Lock()
	r.lastDraw = time.Time{}
	r.mu.Unlock()
	r.onProgress(3, 3)

	out := buf.String()
	for _, want := range []string{"stamping 1/3", "stamping 2/3", "stamping 3/3"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in non-TTY output:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\r") {
		t.Errorf("non-TTY output should not contain carriage returns: %q", out)
	}
}

func TestStampProgress_TTY_UsesCarriageReturnsAndClears(t *testing.T) {
	// Pick a total above warmSuppressThreshold so we get the cold-path
	// live counter rather than the warm "preparing sandbox" line.
	r, buf := newTestRenderer(true)
	r.onProgress(1, 30)
	r.mu.Lock()
	r.lastDraw = time.Time{}
	r.mu.Unlock()
	r.onProgress(30, 30)

	out := buf.String()
	if !strings.Contains(out, "\r[ stamping") {
		t.Errorf("TTY output missing \\r-prefixed live counter: %q", out)
	}
	if !r.finished {
		t.Errorf("renderer should mark finished after done==total")
	}
}

func TestStampProgress_TTY_WarmSuppress(t *testing.T) {
	r, buf := newTestRenderer(true)
	r.onProgress(1, 5)
	r.mu.Lock()
	r.lastDraw = time.Time{}
	r.mu.Unlock()
	r.onProgress(5, 5)

	out := buf.String()
	if !strings.Contains(out, "preparing sandbox") {
		t.Errorf("warm path should emit preparing-sandbox hint, got: %q", out)
	}
	if strings.Contains(out, "[ stamping") {
		t.Errorf("warm path should NOT emit per-job counter, got: %q", out)
	}
}

func TestStampProgress_ThrottleSuppressesIntermediate(t *testing.T) {
	buf := &bytes.Buffer{}
	r := &stampProgressRenderer{
		w:        buf,
		tty:      false,
		throttle: 10 * time.Second, // effectively block intermediate draws
	}
	r.onProgress(1, 10)
	r.onProgress(2, 10)
	r.onProgress(3, 10)
	// Only the FIRST call (lastDraw == zero time, throttle not yet
	// blocking) makes it through; the rest are throttled. Force the
	// final draw by jumping to done==total which bypasses throttle.
	r.onProgress(10, 10)

	out := buf.String()
	lines := strings.Count(out, "\n")
	// Expected lines: first draw + final (done==total) = 2.
	if lines > 2 {
		t.Errorf("expected throttle to limit to 2 lines, got %d:\n%s", lines, out)
	}
	if !strings.Contains(out, "stamping 10/10") {
		t.Errorf("final draw missing in throttled output: %s", out)
	}
}

func TestStampProgress_NoRegressionOnDuplicateDone(t *testing.T) {
	r, buf := newTestRenderer(false)
	r.onProgress(5, 10)
	// Reset lastDraw so the throttle does not interfere; done<=lastDone guards
	// against re-draw, not the throttle — this reset lets us prove the no-op
	// is due to the done-regression check, not the timer.
	r.mu.Lock()
	r.lastDraw = time.Time{}
	r.mu.Unlock()
	// done <= lastDone is silently dropped.
	r.onProgress(5, 10)
	r.onProgress(3, 10)

	if c := strings.Count(buf.String(), "stamping"); c != 1 {
		t.Errorf("duplicate/regress events should not draw, got %d lines:\n%s",
			c, buf.String())
	}
}
