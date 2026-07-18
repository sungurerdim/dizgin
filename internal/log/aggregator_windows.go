// SPDX-License-Identifier: MIT

//go:build windows

package log

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// aggregator state. The aggregator is started at most once per process
// and runs in a single goroutine that polls the source log files every
// pollInterval. Keeping the goroutine count fixed avoids fanning out
// fsnotify watchers (and their per-file handle costs) just for a debug
// feature.
var (
	aggregatorOnce sync.Once
	aggregatorStop chan struct{}
)

const (
	pollInterval = 250 * time.Millisecond
	// aggregatorOutFile is the merged, layer-prefixed log the assistant
	// reads to triage. Fixed name + fixed location matches the rest of
	// the framework: zero per-session ID chasing.
	aggregatorOutFile = "dizgin-debug.log"
)

// StartAggregator launches the background tail-merger when verbose mode
// is on AND propagation is requested (DIZGIN_DEBUG=all). For the local
// "DIZGIN_DEBUG=1" mode the per-component logs already land in
// %ProgramData%\dizgin\logs and are read manually; the aggregator's
// chronological merge only adds value when the user wants the whole
// chain (broker + runhcs + dizgin-init + tool stderr) in one stream.
//
// Idempotent: subsequent calls are no-ops. Stop with StopAggregator.
func StartAggregator() {
	if !IsVerbose() || !VerbosePropagate() {
		return
	}
	aggregatorOnce.Do(func() {
		aggregatorStop = make(chan struct{})
		go aggregatorLoop(aggregatorStop)
	})
}

// StopAggregator signals the aggregator goroutine to exit. Safe to call
// even when the aggregator was never started — the channel is nil-checked.
func StopAggregator() {
	if aggregatorStop == nil {
		return
	}
	select {
	case <-aggregatorStop:
		// already closed
	default:
		close(aggregatorStop)
	}
}

// aggregatorLoop watches the DIZGIN log set and tees new bytes (with a
// `[<layer>]` prefix per source file) to dizgin-debug.log. Polled, not
// fsnotify — periodic re-read is plenty for debug output and removes
// a dep + a Windows-quirky watcher.
func aggregatorLoop(stop <-chan struct{}) {
	progData := os.Getenv("ProgramData")
	if progData == "" {
		progData = `C:\ProgramData`
	}
	logDir := filepath.Join(progData, brand.Name, "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "aggregator: mkdir %s: %v\n", logDir, err)
		return
	}
	outPath := filepath.Join(logDir, aggregatorOutFile)
	out, err := os.OpenFile(outPath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aggregator: open %s: %v\n", outPath, err)
		return
	}
	defer func() { _ = out.Close() }()
	_, _ = fmt.Fprintf(out, "=== dizgin debug aggregator started %s ===\n", time.Now().Format(time.RFC3339))

	type source struct {
		path  string
		layer string
		pos   int64
	}
	sources := []*source{
		{path: filepath.Join(logDir, "daemon.log"), layer: "broker"},
		{path: filepath.Join(logDir, "latest-shim.log"), layer: "runhcs-shim"},
		{path: filepath.Join(logDir, "latest-vm.log"), layer: "runhcs-vm"},
		{path: filepath.Join(logDir, "latest-runhcs.stderr.log"), layer: "runhcs-stderr"},
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			_, _ = fmt.Fprintf(out, "=== aggregator stopped %s ===\n", time.Now().Format(time.RFC3339))
			return
		case <-ticker.C:
			for _, s := range sources {
				if drained, err := drainAppend(out, s.path, s.layer, s.pos); err == nil {
					s.pos += drained
				}
			}
		}
	}
}

// drainAppend reads any new bytes appended to path since pos, tags each
// line with `[<layer>]`, and writes the result to out. Returns the
// number of bytes consumed so the caller can advance its position.
//
// Truncation handling: when the file shrinks (a fresh `latest-*.log`
// was written via O_TRUNC), pos is reset to zero so the new content is
// streamed from the start. Without this the aggregator would skip the
// next runhcs invocation entirely until the file grew past the previous
// size.
func drainAppend(out io.Writer, path, layer string, pos int64) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	if info.Size() < pos {
		pos = 0
	}
	if info.Size() == pos {
		return 0, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(pos, io.SeekStart); err != nil {
		return 0, err
	}
	r := bufio.NewReader(f)
	var consumed int64
	for {
		line, err := r.ReadString('\n')
		if len(line) > 0 {
			_, _ = fmt.Fprintf(out, "[%s] %s", layer, ensureNewline(line))
			consumed += int64(len(line))
		}
		if err != nil {
			break
		}
	}
	return consumed, nil
}

func ensureNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}
