// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestAccessTelemetry_NodeEnoent(t *testing.T) {
	a := newAccessTelemetry()
	_, _ = a.Write([]byte("Error: ENOENT: no such file or directory, open '/etc/secret.txt'\n"))
	paths := a.uniquePaths()
	if len(paths) != 1 || paths[0] != "/etc/secret.txt" {
		t.Errorf("paths: got %v, want [/etc/secret.txt]", paths)
	}
}

func TestAccessTelemetry_PythonFileNotFound(t *testing.T) {
	a := newAccessTelemetry()
	_, _ = a.Write([]byte("FileNotFoundError: [Errno 2] No such file or directory: '/home/user/.cache/cfg'\n"))
	paths := a.uniquePaths()
	if len(paths) != 1 || paths[0] != "/home/user/.cache/cfg" {
		t.Errorf("paths: got %v", paths)
	}
}

func TestAccessTelemetry_GoOpen(t *testing.T) {
	a := newAccessTelemetry()
	_, _ = a.Write([]byte("open C:\\Users\\X\\config.toml: no such file or directory\n"))
	paths := a.uniquePaths()
	if len(paths) != 1 {
		t.Fatalf("paths: got %v", paths)
	}
	if !strings.Contains(paths[0], "config.toml") {
		t.Errorf("unexpected path: %q", paths[0])
	}
}

func TestAccessTelemetry_WindowsCmdCannotFind(t *testing.T) {
	a := newAccessTelemetry()
	_, _ = a.Write([]byte("The system cannot find the file specified: D:\\data\\missing.json\n"))
	paths := a.uniquePaths()
	if len(paths) < 1 {
		t.Fatalf("no paths extracted: %v", paths)
	}
}

func TestAccessTelemetry_DedupesAcrossLines(t *testing.T) {
	a := newAccessTelemetry()
	_, _ = a.Write([]byte("ENOENT: no such file or directory, open '/etc/a'\n"))
	_, _ = a.Write([]byte("ENOENT: no such file or directory, open '/etc/a'\n"))
	_, _ = a.Write([]byte("ENOENT: no such file or directory, open '/etc/b'\n"))
	paths := a.uniquePaths()
	if len(paths) != 2 {
		t.Errorf("expected 2 unique paths, got %v", paths)
	}
}

func TestAccessTelemetry_IgnoresNonPathNoise(t *testing.T) {
	a := newAccessTelemetry()
	_, _ = a.Write([]byte("hello world\n"))
	_, _ = a.Write([]byte("some error message without paths\n"))
	paths := a.uniquePaths()
	if len(paths) != 0 {
		t.Errorf("expected no paths, got %v", paths)
	}
}

func TestAccessTelemetry_BufferBound(t *testing.T) {
	a := newAccessTelemetry()
	a.maxBuf = 128
	noise := strings.Repeat("noise-noise-noise\n", 50)
	_, _ = a.Write([]byte(noise))
	_, _ = a.Write([]byte("ENOENT: no such file or directory, open '/tmp/late.txt'\n"))
	paths := a.uniquePaths()
	if len(paths) == 0 {
		t.Errorf("latest match must survive buffer trim, got %v", paths)
	}
}

func TestAccessTelemetry_ReportWritesNothingWhenEmpty(t *testing.T) {
	var buf bytes.Buffer
	a := newAccessTelemetry()
	got := a.Report(&buf)
	if buf.Len() != 0 {
		t.Errorf("unexpected report output: %q", buf.String())
	}
	if len(got) != 0 {
		t.Errorf("paths: got %v, want empty", got)
	}
}

func TestAccessTelemetry_ReportWritesWhenPopulated(t *testing.T) {
	var buf bytes.Buffer
	a := newAccessTelemetry()
	_, _ = a.Write([]byte("ENOENT: no such file or directory, open '/missing'\n"))
	paths := a.Report(&buf)
	if len(paths) != 1 {
		t.Fatalf("paths: got %v", paths)
	}
	if !strings.Contains(buf.String(), "/missing") {
		t.Errorf("report should mention the path: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "dizgin add-path") {
		t.Errorf("report should hint at dizgin add-path: %q", buf.String())
	}
}

func TestNewStderrTee_NilPassesThrough(t *testing.T) {
	w := newStderrTee(nil)
	if w == nil {
		t.Error("nil telemetry should still return a writer")
	}
}

func TestAccessTelemetry_LooksLikePath(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"/tmp/x", true},
		{`C:\foo\bar`, true},
		{"C:", false},
		{"hello", false},
		{"a/b", false},
		{"value", false},
	}
	for _, c := range cases {
		got := looksLikePath(c.in)
		if got != c.want {
			t.Errorf("looksLikePath(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
