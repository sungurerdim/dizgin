// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"bytes"
	"strings"
	"testing"
)

func TestAccessRecorder_capturesDenialPatterns(t *testing.T) {
	var sink bytes.Buffer
	r := newAccessRecorder(&sink)

	inputs := []string{
		"normal line 1\n",
		"cat: /home/user/.ssh/id_rsa: Permission denied\n",
		"more normal output\n",
		"Erişim engellendi.\n",
		"open /tmp/foo: permission denied\n",
		"Access is denied.\n",
		"operation not permitted on /etc/shadow\n",
	}
	for _, s := range inputs {
		if _, err := r.Write([]byte(s)); err != nil {
			t.Fatalf("Write(%q): %v", s, err)
		}
	}
	r.flushPartial()

	hits := r.Hits()
	if len(hits) != 5 {
		t.Errorf("expected 5 denial hits, got %d: %v", len(hits), hits)
	}

	// All inputs must reach the wrapped writer untouched.
	if sink.String() != strings.Join(inputs, "") {
		t.Errorf("forwarded bytes diverged from input:\nwant=%q\ngot=%q",
			strings.Join(inputs, ""), sink.String())
	}
}

func TestAccessRecorder_partialFinalLine(t *testing.T) {
	var sink bytes.Buffer
	r := newAccessRecorder(&sink)

	// A tool emits a final error line without a trailing newline.
	_, _ = r.Write([]byte("Access denied"))
	if len(r.Hits()) != 0 {
		t.Errorf("partial line should not register before flush; got %v", r.Hits())
	}
	r.flushPartial()
	if hits := r.Hits(); len(hits) != 1 || !strings.Contains(hits[0], "Access denied") {
		t.Errorf("flushPartial did not capture trailing line; got %v", hits)
	}
}

func TestAccessRecorder_crlfLineSplitter(t *testing.T) {
	var sink bytes.Buffer
	r := newAccessRecorder(&sink)
	_, _ = r.Write([]byte("Access is denied\r\nfoo bar baz\r\n"))
	r.flushPartial()
	hits := r.Hits()
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d: %v", len(hits), hits)
	}
	if !strings.Contains(hits[0], "Access is denied") {
		t.Errorf("hit content unexpected: %q", hits[0])
	}
}

func TestIsDenialLine(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"Access is denied.", true},
		{"access denied", true},
		{"ACCESS DENIED!", true},
		{"permission denied", true},
		{"erişim engellendi", true},
		{"Erişim engellendi.", true},
		{"Operation Not Permitted", true},

		{"normal output", false},
		{"hello world", false},
		{"Denied is access (yoda mode)", false}, // exact phrase only
		{"", false},
	}
	for _, c := range cases {
		if got := isDenialLine(c.line); got != c.want {
			t.Errorf("isDenialLine(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

func TestPrintLearnSummary(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		var b bytes.Buffer
		PrintLearnSummary(&b, nil)
		got := b.String()
		if !strings.Contains(got, "No access-denial") {
			t.Errorf("empty summary lacks expected text:\n%s", got)
		}
	})

	t.Run("with_hits", func(t *testing.T) {
		var b bytes.Buffer
		PrintLearnSummary(&b, []string{
			"cat: /home/user/.ssh/id_rsa: Permission denied",
			"Erişim engellendi.",
		})
		got := b.String()
		if !strings.Contains(got, "Captured 2 access-denial line(s)") {
			t.Errorf("missing count line:\n%s", got)
		}
		if !strings.Contains(got, "Permission denied") {
			t.Errorf("missing first hit:\n%s", got)
		}
		if !strings.Contains(got, "Erişim engellendi") {
			t.Errorf("missing second hit:\n%s", got)
		}
	})

	t.Run("truncates_long_line", func(t *testing.T) {
		var b bytes.Buffer
		longLine := "Permission denied " + strings.Repeat("x", 300)
		PrintLearnSummary(&b, []string{longLine})
		got := b.String()
		if !strings.Contains(got, "...") {
			t.Errorf("expected truncation marker in long-line summary:\n%s", got)
		}
	})
}

func TestAccessRecorder_PathHits(t *testing.T) {
	var sink bytes.Buffer
	r := newAccessRecorder(&sink)
	inputs := []string{
		"cat: /home/user/.ssh/id_rsa: Permission denied\n",
		// Note: lines below must contain a denial keyword to be
		// recorded; "Cannot open" alone is not in denialPatterns.
		"Permission denied: 'C:\\Users\\me\\.aws\\credentials'\n",
		"normal line, no denial\n",
		"open /tmp/foo: permission denied\n",
		"cat: /home/user/.ssh/id_rsa: Permission denied\n", // duplicate
		"Erişim engellendi.\n",                             // denial w/o path
	}
	for _, s := range inputs {
		if _, err := r.Write([]byte(s)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	r.flushPartial()
	paths := r.PathHits()
	// Expect 3 unique paths: /home/user/.ssh/id_rsa (dedup'd), the
	// quoted Windows path, and /tmp/foo. The Turkish "engellendi"
	// line has no extractable path so it should produce no entry.
	if len(paths) != 3 {
		t.Fatalf("expected 3 unique paths, got %d: %v", len(paths), paths)
	}
	wantContains := []string{
		"/home/user/.ssh/id_rsa",
		`C:\Users\me\.aws\credentials`,
		"/tmp/foo",
	}
	for _, w := range wantContains {
		found := false
		for _, p := range paths {
			if strings.EqualFold(p, w) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing expected path %q in: %v", w, paths)
		}
	}
}

func TestAccessRecorder_PathHits_EmptyOnNoDenials(t *testing.T) {
	var sink bytes.Buffer
	r := newAccessRecorder(&sink)
	if _, err := r.Write([]byte("normal output\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	r.flushPartial()
	if got := r.PathHits(); got != nil {
		t.Errorf("PathHits should be nil when no denial lines: %v", got)
	}
}

func TestExtractPathsFromLine(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		expect string
	}{
		{
			name:   "unix_colon_prefix",
			line:   "cat: /home/user/.ssh/id_rsa: Permission denied",
			expect: "/home/user/.ssh/id_rsa",
		},
		{
			name:   "windows_quoted",
			line:   `Cannot open file 'C:\Users\me\file'`,
			expect: `C:\Users\me\file`,
		},
		{
			name:   "windows_bare",
			line:   `Access denied: C:\Users\me\.ssh\id_rsa`,
			expect: `C:\Users\me\.ssh\id_rsa`,
		},
		{
			name:   "no_path",
			line:   "Erişim engellendi.",
			expect: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractPathsFromLine(tc.line)
			if tc.expect == "" {
				if len(got) != 0 {
					t.Errorf("expected no paths, got %v", got)
				}
				return
			}
			found := false
			for _, p := range got {
				if strings.EqualFold(p, tc.expect) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("missing expected %q in %v", tc.expect, got)
			}
		})
	}
}
