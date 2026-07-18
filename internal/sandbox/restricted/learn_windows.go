// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"bytes"
	"io"
	"regexp"
	"strings"
	"sync"
)

// accessRecorder is an io.Writer that forwards every byte to a target
// (typically os.Stderr) and, in the background, scans whole lines for
// access-denial patterns. It is wired into dizgin's `--learn` mode so the
// user can see a post-session summary of which paths the sandboxed
// tool tried to access but was DENY-ACE'd against.
//
// Production stdio handling is unaffected: forwarding happens before
// the scan, so a slow scanner cannot stall the child's stderr write
// path. The lock is taken only around buffer append + scan; the write
// to target runs lock-free.
type accessRecorder struct {
	target io.Writer

	mu   sync.Mutex
	buf  bytes.Buffer
	hits []string
}

// denialPatterns matches the prefix/suffix shapes Windows / Linux /
// macOS tools use when reporting access-denied conditions. Case-
// insensitive.
//
// Locale notes: cmd.exe on a Turkish-locale Windows host emits
// "Erişim engellendi." in the OEM code page (CP1254/CP857), not UTF-8.
// The `ş` byte therefore varies by code page, so we match the
// unambiguous ASCII suffix "engellendi" alone — same trick the
// equivalent German ("verweigert"), Spanish ("denegado") and other
// locale lines need. The English/golang/python forms are pure ASCII
// and need no special handling.
var denialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)access\s+(is\s+)?denied`),
	regexp.MustCompile(`(?i)permission\s+denied`),
	regexp.MustCompile(`(?i)operation\s+not\s+permitted`),
	regexp.MustCompile(`(?i)engellendi`), // Turkish (Erişim engellendi)
	regexp.MustCompile(`(?i)verweigert`), // German (Zugriff verweigert)
	regexp.MustCompile(`(?i)denegado`),   // Spanish (Permiso denegado)
}

// newAccessRecorder constructs a recorder that mirrors writes to
// target. Pass os.Stderr in production; tests can substitute an
// in-memory buffer.
func newAccessRecorder(target io.Writer) *accessRecorder {
	return &accessRecorder{target: target}
}

// Write forwards p to target, then queues whatever complete lines
// accumulated for the denial scan. Returns the byte count target
// accepted so the caller's accounting matches a plain io.Writer.
func (r *accessRecorder) Write(p []byte) (int, error) {
	n, err := r.target.Write(p)
	if err != nil {
		return n, err
	}
	r.mu.Lock()
	r.buf.Write(p)
	for {
		line, ok := r.takeLine()
		if !ok {
			break
		}
		if isDenialLine(line) {
			r.hits = append(r.hits, line)
		}
	}
	r.mu.Unlock()
	return n, nil
}

// takeLine consumes one complete line (terminated by \n or \r\n) from
// the buffer and returns the line content without the terminator.
// Caller must hold r.mu.
func (r *accessRecorder) takeLine() (string, bool) {
	data := r.buf.Bytes()
	i := bytes.IndexAny(data, "\r\n")
	if i < 0 {
		return "", false
	}
	line := string(bytes.TrimRight(data[:i+1], "\r\n"))
	end := i + 1
	// Consume the second byte of a CRLF pair (without swallowing a
	// trailing standalone \r that belongs to the next line).
	if end < len(data) && (data[end] == '\n' || data[end] == '\r') && data[i] != data[end] {
		end++
	}
	r.buf.Next(end)
	return line, true
}

// isDenialLine reports whether line matches any denialPatterns regex.
// Exported for tests in the same package; callers should prefer the
// Hits() method on accessRecorder for production use.
func isDenialLine(line string) bool {
	for _, re := range denialPatterns {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

// Hits returns a copy of the captured denial lines. Returned slice is
// owned by the caller; subsequent Write calls do not mutate it.
func (r *accessRecorder) Hits() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.hits))
	copy(out, r.hits)
	return out
}

// pathExtractPatterns captures the path portion out of a denial line.
// Order matters — more specific patterns first so the generic absolute-
// path tail does not consume part of a "cat: /foo: ..." prefix.
//
// The patterns are deliberately conservative: they only match absolute
// paths (drive letter or POSIX-style /) so that error messages that
// reference a bare filename are not surfaced as a permission target the
// user could meaningfully grant. False negatives are fine — the user
// can edit ~/.dizgin/permissions/<tool>.yaml by hand.
var pathExtractPatterns = []*regexp.Regexp{
	// "cat: /home/user/.ssh/id_rsa: Permission denied"
	regexp.MustCompile(`(?i)\b\w+:\s+(/[^:\s]+|[A-Za-z]:[\\/][^:\s]+):`),
	// "Cannot open file 'C:\Users\me\.ssh\known_hosts'"
	regexp.MustCompile(`(?i)['"]([A-Za-z]:[\\/][^'"]+)['"]`),
	regexp.MustCompile(`(?i)['"](/[^'"]+)['"]`),
	// Bare absolute path anywhere in the line — fallback.
	regexp.MustCompile(`([A-Za-z]:[\\/][^\s,;]+)`),
	regexp.MustCompile(`\s(/[^\s,;]+)`),
}

// PathHits returns the deduplicated set of absolute paths the recorder
// extracted from denial lines. Returned slice ordering is stable
// (first occurrence wins) so the interactive prompt walks paths in the
// order the tool actually hit them. Case-insensitive dedup on Windows.
//
// Returns nil when no denial line yielded an extractable path; callers
// should treat nil and empty identically.
func (r *accessRecorder) PathHits() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.hits) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(r.hits))
	var out []string
	for _, h := range r.hits {
		for _, p := range extractPathsFromLine(h) {
			key := strings.ToLower(p)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, p)
		}
	}
	return out
}

// extractPathsFromLine returns the path captured by the first matching
// pattern, or nil when none fires. The patterns are listed most-
// specific first; once one matches, the remaining (looser) patterns are
// skipped to avoid the same line surfacing twice under different forms
// (e.g. "cat: /foo: Permission denied" matching both the colon-prefix
// pattern as "/foo" and the bare-path tail as "/foo:").
//
// Trailing colon trim handles error-format separators like
// "/path/to/file:" where ":" is the message separator, not part of
// the actual path the user wants to grant access to.
func extractPathsFromLine(line string) []string {
	for _, pat := range pathExtractPatterns {
		m := pat.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		p := strings.TrimRight(strings.TrimSpace(m[1]), ":")
		if p == "" {
			continue
		}
		return []string{p}
	}
	return nil
}

// flushPartial drains any remaining buffered bytes through the scan
// after a stream ends without a terminating newline. Some tools emit
// their final error line without \n; without this flush we would miss
// the very last denial of the session.
func (r *accessRecorder) flushPartial() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.buf.Len() == 0 {
		return
	}
	tail := r.buf.String()
	r.buf.Reset()
	if isDenialLine(tail) {
		r.hits = append(r.hits, tail)
	}
}
