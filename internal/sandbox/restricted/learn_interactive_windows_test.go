// SPDX-License-Identifier: MIT

//go:build windows

package restricted

// TST-01 — PromptForPermissions / promptOne classification loop.
//
// Note: isStdinTTY() checks os.Stdin — the test runner's stdin is always a
// pipe (non-TTY), so PromptForPermissions returns early with the "not a TTY"
// message. We test the non-TTY path directly on PromptForPermissions, and
// test promptOne (the per-path classification loop) in isolation via its own
// exported-within-package call.

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

// ---- promptOne (package-internal, called from within the package) ----

func TestPromptOne_RecognisedVerbs(t *testing.T) {
	cases := []struct {
		name  string
		input string // text fed to the reader
		want  string
	}{
		{"rw", "rw\n", "rw"},
		{"ro", "ro\n", "ro"},
		{"deny", "deny\n", "deny"},
		{"skip", "skip\n", "skip"},
		{"case_insensitive_RW", "RW\n", "rw"},
		{"case_insensitive_Deny", "DENY\n", "deny"},
		{"empty_line_is_skip", "\n", "skip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var w bytes.Buffer
			r := bufio.NewReader(strings.NewReader(tc.input))
			got := promptOne(&w, r, 1, 3, `C:\Users\testuser\projects\app`)
			if got != tc.want {
				t.Errorf("promptOne(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestPromptOne_UnknownVerbRepromptsUntilEOF(t *testing.T) {
	// "bad\nbad2\nrw\n" — two invalid choices then a valid one.
	var w bytes.Buffer
	r := bufio.NewReader(strings.NewReader("bad\nbad2\nrw\n"))
	got := promptOne(&w, r, 1, 1, `C:\Users\testuser\projects\app`)
	if got != "rw" {
		t.Errorf("expected rw after recovery from invalid input, got %q", got)
	}
	out := w.String()
	if !strings.Contains(out, "unknown choice") {
		t.Errorf("expected 'unknown choice' reprompt in output:\n%s", out)
	}
}

func TestPromptOne_EOFDefaultsToSkip(t *testing.T) {
	// Empty reader produces immediate EOF.
	var w bytes.Buffer
	r := bufio.NewReader(strings.NewReader(""))
	got := promptOne(&w, r, 1, 1, `C:\Users\testuser\projects\main.go`)
	if got != "skip" {
		t.Errorf("EOF should default to skip; got %q", got)
	}
}

func TestPromptOne_UnknownThenEOFDefaultsToSkip(t *testing.T) {
	// An invalid choice followed by EOF should still land on skip.
	var w bytes.Buffer
	r := bufio.NewReader(strings.NewReader("bogus"))
	got := promptOne(&w, r, 1, 1, `C:\Users\testuser\documents\report.pdf`)
	if got != "skip" {
		t.Errorf("unknown + EOF should default to skip; got %q", got)
	}
}

func TestPromptOne_LongPathTruncated(t *testing.T) {
	// Paths longer than 100 chars must be truncated with a "..." prefix in
	// the display line — promptOne shortens to 97 chars + "...".
	longPath := `C:\Users\testuser\` + strings.Repeat("subdir\\", 20) + "file.go"
	var w bytes.Buffer
	r := bufio.NewReader(strings.NewReader("skip\n"))
	promptOne(&w, r, 1, 1, longPath)
	out := w.String()
	if !strings.Contains(out, "...") {
		t.Errorf("expected '...' truncation for path > 100 chars in output:\n%s", out)
	}
}

func TestPromptOne_SensitivePathWarning(t *testing.T) {
	// A path the security package classifies as sensitive should trigger the
	// "credential material" warning line.
	t.Setenv("USERPROFILE", `C:\Users\testuser`)
	var w bytes.Buffer
	r := bufio.NewReader(strings.NewReader("deny\n"))
	promptOne(&w, r, 1, 1, `C:\Users\testuser\.ssh\id_rsa`)
	out := w.String()
	if !strings.Contains(out, "credential material") {
		t.Errorf("expected credential-material warning for sensitive path:\n%s", out)
	}
}

func TestPromptOne_NonSensitivePathNoWarning(t *testing.T) {
	t.Setenv("USERPROFILE", `C:\Users\testuser`)
	var w bytes.Buffer
	r := bufio.NewReader(strings.NewReader("rw\n"))
	promptOne(&w, r, 1, 1, `C:\Users\testuser\projects\myapp\main.go`)
	out := w.String()
	if strings.Contains(out, "credential material") {
		t.Errorf("unexpected credential-material warning for non-sensitive path:\n%s", out)
	}
}

// ---- PromptForPermissions — non-TTY path (always true in test runner) ----

func TestPromptForPermissions_NonTTY_ReturnsExistingUnchanged(t *testing.T) {
	// The test runner's stdin is a pipe → isStdinTTY() is false → the function
	// must return existing overrides unchanged and print the skip message.
	existing := Overrides{
		RW:   []string{`c:\users\testuser\projects\app`},
		RO:   []string{`c:\windows\system32\foo.dll`},
		Deny: []string{`c:\users\testuser\.gnupg`},
	}
	paths := []string{`C:\Users\testuser\projects\data.json`}
	var w bytes.Buffer
	r := strings.NewReader("rw\n") // never read in non-TTY path
	got := PromptForPermissions(&w, r, paths, existing)

	out := w.String()
	if !strings.Contains(out, "not a TTY") {
		t.Errorf("expected 'not a TTY' message in non-TTY mode:\n%s", out)
	}
	// Overrides must be unchanged.
	if !overridesEqual(got, existing) {
		t.Errorf("non-TTY must return existing unchanged\ngot  %+v\nwant %+v", got, existing)
	}
}

func TestPromptForPermissions_EmptyPaths_ReturnsExisting(t *testing.T) {
	existing := Overrides{RW: []string{`c:\users\testuser\projects`}}
	var w bytes.Buffer
	got := PromptForPermissions(&w, strings.NewReader(""), nil, existing)
	if !overridesEqual(got, existing) {
		t.Errorf("empty paths should return existing; got %+v, want %+v", got, existing)
	}
	// No output expected (empty paths exits before the TTY check).
	if w.Len() != 0 {
		t.Errorf("expected no output for empty path list; got: %s", w.String())
	}
}

// ---- sliceContainsFold ----

func TestSliceContainsFold(t *testing.T) {
	s := []string{`C:\Users\Me\.ssh`, `C:\Windows\System32`}
	cases := []struct {
		target string
		want   bool
	}{
		{`C:\Users\Me\.ssh`, true},
		{`c:\users\me\.ssh`, true},    // lowercase variant
		{`C:\WINDOWS\SYSTEM32`, true}, // all-caps variant
		{`C:\Users\Me\.aws`, false},   // not present
		{``, false},                   // empty
		{`C:\Users\Me\.ssh\`, false},  // trailing slash changes the string
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			got := sliceContainsFold(s, tc.target)
			if got != tc.want {
				t.Errorf("sliceContainsFold(%q) = %v, want %v", tc.target, got, tc.want)
			}
		})
	}
}
