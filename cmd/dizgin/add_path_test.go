// SPDX-License-Identifier: MIT

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// TestParseAddPathFlags_Help verifies --help short-circuits with no error and
// no paths, per the documented "paths is nil and err is nil" contract that
// callers rely on to distinguish help from a real invocation.
func TestParseAddPathFlags_Help(t *testing.T) {
	tool, ro, suggest, paths, err := parseAddPathFlags([]string{"--help"})
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if tool != "" || ro || suggest || paths != nil {
		t.Errorf("got tool=%q ro=%v suggest=%v paths=%v, want all zero-value", tool, ro, suggest, paths)
	}
}

// TestParseAddPathFlags_ToolRequiresValue catches a dangling --tool flag
// (e.g. a shell wrapper that drops the next arg) instead of silently
// treating whatever comes next as the tool name.
func TestParseAddPathFlags_ToolRequiresValue(t *testing.T) {
	_, _, _, _, err := parseAddPathFlags([]string{"--tool"})
	if err == nil {
		t.Fatal("err = nil, want error for --tool with no value")
	}
}

func TestParseAddPathFlags_ToolEqualsStyle(t *testing.T) {
	tool, _, _, paths, err := parseAddPathFlags([]string{"--tool=claude", "/tmp/x"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if tool != "claude" {
		t.Errorf("tool = %q, want %q", tool, "claude")
	}
	if len(paths) != 1 || paths[0] != "/tmp/x" {
		t.Errorf("paths = %v, want [/tmp/x]", paths)
	}
}

func TestParseAddPathFlags_UnknownFlagRejected(t *testing.T) {
	_, _, _, _, err := parseAddPathFlags([]string{"--bogus"})
	if err == nil {
		t.Fatal("err = nil, want error for unrecognized flag")
	}
}

func TestParseAddPathFlags_ReadOnlyAndPaths(t *testing.T) {
	t.Setenv(brand.Env("TOOL"), "") // deterministic: no ambient $DIZGIN_TOOL
	tool, ro, suggest, paths, err := parseAddPathFlags([]string{"--ro", "/a", "/b"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !ro || suggest {
		t.Errorf("ro=%v suggest=%v, want ro=true suggest=false", ro, suggest)
	}
	if tool != "" {
		t.Errorf("tool = %q, want empty (no --tool, no $DIZGIN_TOOL in test env)", tool)
	}
	if len(paths) != 2 || paths[0] != "/a" || paths[1] != "/b" {
		t.Errorf("paths = %v, want [/a /b]", paths)
	}
}

func TestParseAddPathFlags_SuggestFlag(t *testing.T) {
	_, _, suggest, _, err := parseAddPathFlags([]string{"--suggest", "/tmp"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !suggest {
		t.Error("suggest = false, want true")
	}
}

// TestBuildPathEntries_ResolvesAndTags verifies happy-path entries get an
// absolute path, the requested mode, and the "manual" source tag that
// downstream profile-merge logic depends on.
func TestBuildPathEntries_ResolvesAndTags(t *testing.T) {
	dir := t.TempDir()
	entries, err := buildPathEntries([]string{dir}, "rw")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %v, want 1 entry", entries)
	}
	if entries[0].Mode != "rw" || entries[0].Source != "manual" {
		t.Errorf("entry = %+v, want Mode=rw Source=manual", entries[0])
	}
	abs, _ := filepath.Abs(dir)
	if entries[0].Path != abs {
		t.Errorf("Path = %q, want %q", entries[0].Path, abs)
	}
}

// TestBuildPathEntries_RefusesRiskyPath is a regression test for the R1
// red line: add-path must never silently accept a path on the sensitive
// deny-list (here, a bare .ssh directory) even when explicitly requested
// by the user — the whole point of the SSOT deny-list is that it cannot
// be bypassed via this command.
func TestBuildPathEntries_RefusesRiskyPath(t *testing.T) {
	_, err := buildPathEntries([]string{"/home/test/.ssh"}, "rw")
	if err == nil {
		t.Fatal("err = nil, want refusal for risky path /home/test/.ssh")
	}
	if !strings.Contains(err.Error(), "refusing risky path") {
		t.Errorf("err = %v, want it to mention refusing a risky path", err)
	}
}

func TestBuildPathEntries_EmptyInput(t *testing.T) {
	entries, err := buildPathEntries(nil, "ro")
	if err != nil {
		t.Fatalf("err = %v, want nil for empty input", err)
	}
	if len(entries) != 0 {
		t.Errorf("entries = %v, want empty", entries)
	}
}
