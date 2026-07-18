// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/security"
)

// accessEntry pairs a referenced path with the central deny-list verdict.
// The interactive 5-way prompt that consumed mode + risk metadata was
// retired in iter4 — the lighter post-exit "tool referenced paths" report
// surfaces non-risky paths to the user, who can opt them into the profile
// via `dizgin add-path <path>`.
type accessEntry struct {
	Path       string
	Risky      bool
	RiskReason security.RiskyReason
}

// accessPathPatterns is the trimmed core regex library — five patterns
// that cover the bulk of "tool tried to read X" surface across the
// runtimes we ship profiles for (Node, Python, Go, shells, Windows
// runtime). Each pattern requires a clear error-message anchor so the
// false-positive rate stays low; locale-specific failure messages fall
// through to the argv-based NoteFromArgs fallback below.
//
// Earlier iterations carried 20+ patterns with per-pattern READ/WRITE
// mode tagging plus contextual write-hint refinement to drive the
// 5-way prompt's RW/RO default. With the prompt gone, the only
// downstream consumer is the Report() listing — path-only metadata
// suffices.
var accessPathPatterns = []*regexp.Regexp{
	// ENOENT (Node.js, libuv, generic POSIX).
	regexp.MustCompile(`ENOENT[^']*'([^']+)'`),
	// Python FileNotFoundError / PermissionError.
	regexp.MustCompile(`(?:FileNotFoundError|PermissionError):[^']*'([^']+)'`),
	// Go: "open <path>: no such file or directory"
	regexp.MustCompile(`open\s+([A-Za-z]:\\[^\s:]+|/[^\s:]+):\s+no such file`),
	// Windows cmd.exe / .NET path messages.
	regexp.MustCompile(`(?i)(?:cannot find (?:the (?:file|path) specified|file|path)|FileNotFoundException|DirectoryNotFoundException)[^:]*:?\s*([A-Za-z]:\\[^\s'"]+|/[^\s'"]+)`),
	// Bash / make / cmake-style "<path>: No such file or directory".
	regexp.MustCompile(`([A-Za-z]:\\[^\s:'"]+|/[^\s:'"]+):\s*No such file or directory`),
}

// scannerInitBuf is the initial buffer size for the line scanner in
// uniqueEntries. Sized to cover the majority of lines without growing.
const scannerInitBuf = 64 * 1024 // 64 KiB

// scannerMaxLine is the maximum line length accepted by uniqueEntries.
// Lines longer than this are silently skipped by bufio.Scanner.
const scannerMaxLine = 1 * 1024 * 1024 // 1 MiB

// accessTelemetry observes the tool's combined output while it runs and,
// at exit, lists distinct paths matched by accessPathPatterns. The
// listing is the input for the user's manual decision to expose those
// paths via `dizgin add-path <path>`. Memory is bounded — at most 1 MiB of
// output is retained and the unique path set is capped at 50 entries.
type accessTelemetry struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	seen    map[string]struct{}
	maxBuf  int
	maxSeen int
}

// newAccessTelemetryCore is the platform-agnostic constructor. Platform
// files wrap it with a newAccessTelemetry shim so callers can opt in /
// out per OS via build tags without duplicating the core struct.
func newAccessTelemetryCore() *accessTelemetry {
	return &accessTelemetry{
		seen:    make(map[string]struct{}),
		maxBuf:  1 << 20, // 1 MiB
		maxSeen: 50,
	}
}

// Write implements io.Writer so the observer can be chained into an
// io.MultiWriter alongside os.Stderr / the PTY sink.
func (a *accessTelemetry) Write(p []byte) (int, error) {
	if a == nil {
		return len(p), nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// Drop the oldest bytes when the buffer would grow past maxBuf so the
	// most recent output is always the last thing analysed.
	if a.buf.Len()+len(p) > a.maxBuf {
		overflow := a.buf.Len() + len(p) - a.maxBuf
		if overflow >= a.buf.Len() {
			a.buf.Reset()
		} else {
			a.buf.Next(overflow)
		}
	}
	a.buf.Write(p)
	return len(p), nil
}

// uniquePaths returns the sorted set of distinct paths matched by the
// patterns. Risky paths (security deny-list) are filtered out.
func (a *accessTelemetry) uniquePaths() []string {
	entries := a.uniqueEntries()
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Path)
	}
	return out
}

// uniqueEntries scans the captured output and returns deduplicated access
// entries. Risky paths are dropped silently — the central deny-list
// invariant says they must never reach any user-visible surface.
func (a *accessTelemetry) uniqueEntries() []accessEntry {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	data := a.buf.Bytes()
	a.mu.Unlock()

	found := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, scannerInitBuf), scannerMaxLine)
	for scanner.Scan() {
		line := scanner.Text()
		for _, re := range accessPathPatterns {
			m := re.FindStringSubmatch(line)
			if len(m) < 2 {
				continue
			}
			p := strings.TrimSpace(m[1])
			p = strings.TrimRight(p, `.,;`)
			if p == "" || !looksLikePath(p) {
				continue
			}
			if _, ok := found[p]; ok {
				continue
			}
			found[p] = struct{}{}
			if len(found) >= a.maxSeen {
				goto done
			}
		}
	}
done:

	out := make([]accessEntry, 0, len(found))
	for p := range found {
		risky, reason := security.IsRiskyPath(p)
		if !risky {
			if userRisky, userReason := security.IsUserDenied(p); userRisky {
				risky = true
				reason = userReason
			}
		}
		out = append(out, accessEntry{Path: p, Risky: risky, RiskReason: reason})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// looksLikePath filters out short tokens and things that are clearly not
// file paths (ENV var references, quoted words without separators).
func looksLikePath(s string) bool {
	if len(s) < 4 {
		return false
	}
	hasSep := strings.ContainsAny(s, `\/`)
	windowsDrive := len(s) >= 2 && s[1] == ':' && ((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z'))
	return hasSep || windowsDrive
}

// Report writes a short summary of observed non-risky paths to w and
// returns the full entry list. The on-screen listing closes with a hint
// pointing the user at `dizgin add-path <path>` so they can opt the paths
// into the tool profile on the next invocation.
func (a *accessTelemetry) Report(w io.Writer) []accessEntry {
	entries := a.uniqueEntries()
	if len(entries) == 0 {
		return nil
	}
	visible := 0
	for _, e := range entries {
		if !e.Risky {
			visible++
		}
	}
	if visible == 0 {
		return entries
	}
	_, _ = fmt.Fprintln(w, brand.Name+": tool referenced paths that were not mounted:")
	for _, e := range entries {
		if e.Risky {
			continue
		}
		_, _ = fmt.Fprintf(w, "  - %s\n", e.Path)
	}
	_, _ = fmt.Fprintln(w, "  add a path to the tool profile with: dizgin add-path <path>")
	return entries
}

// NoteFromArgs is the locale-agnostic fallback. When a tool exits with a
// non-zero code, every argv element that looks like an absolute path and
// does not exist on the host filesystem is recorded as a READ access
// candidate — even when the tool's stderr message was localized in a
// language the regex library does not cover.
//
// Skipped argv shapes:
//   - Empty, flag-shaped (-foo, --bar), short non-path tokens.
//   - Paths that exist on the host (the tool's failure was unrelated).
//   - Relative paths (we cannot tell whether they are file references or
//     literal subcommand strings without more context).
func (a *accessTelemetry) NoteFromArgs(args []string, exitCode int) {
	if a == nil || exitCode == 0 {
		return
	}
	for _, arg := range args {
		if arg == "" || strings.HasPrefix(arg, "-") {
			continue
		}
		if !filepath.IsAbs(arg) {
			continue
		}
		if !looksLikePath(arg) {
			continue
		}
		if _, err := os.Stat(arg); err == nil {
			continue
		}
		// Inject a synthetic line that the Node-style ENOENT pattern will
		// pick up on the next uniqueEntries() pass. Single-quote so embedded
		// backslashes survive verbatim.
		a.mu.Lock()
		fmt.Fprintf(&a.buf, "ENOENT: no such file or directory, open '%s'\n", arg)
		a.mu.Unlock()
	}
}

// newStderrTee returns a writer that duplicates writes to os.Stderr and to
// a. When a is nil the returned writer is os.Stderr unchanged.
func newStderrTee(a *accessTelemetry) io.Writer {
	if a == nil {
		return os.Stderr
	}
	return io.MultiWriter(os.Stderr, a)
}
