// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sungurerdim/dizgin/internal/config"
)

func withTempProfilesDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := profilesDir
	profilesDir = dir
	t.Cleanup(func() { profilesDir = old })
	return dir
}

func TestAppendProfileEntries_CreatesScaffold(t *testing.T) {
	dir := withTempProfilesDir(t)
	added, err := AppendProfileEntries("mytool", []config.ConfigDirEntry{
		{Path: `C:\Users\Test\.local\share\pnpm`, Mode: "rw", Source: "auto"},
	})
	if err != nil {
		t.Fatalf("AppendProfileEntries: %v", err)
	}
	if added != 1 {
		t.Errorf("added count = %d, want 1", added)
	}
	body, err := os.ReadFile(filepath.Join(dir, "mytool.yaml"))
	if err != nil {
		t.Fatalf("profile file not written: %v", err)
	}
	s := string(body)
	for _, want := range []string{"name: mytool", "version: 1", "config_dirs:", "pnpm", "mode: rw", "source: auto"} {
		if !strings.Contains(s, want) {
			t.Errorf("profile missing %q: %s", want, s)
		}
	}
}

func TestAppendProfileEntries_IdempotentNoDuplicate(t *testing.T) {
	withTempProfilesDir(t)

	entry := config.ConfigDirEntry{Path: `C:\foo\bar`, Mode: "rw", Source: "auto"}
	if _, err := AppendProfileEntries("tool2", []config.ConfigDirEntry{entry}); err != nil {
		t.Fatal(err)
	}
	added, err := AppendProfileEntries("tool2", []config.ConfigDirEntry{entry})
	if err != nil {
		t.Fatal(err)
	}
	if added != 0 {
		t.Errorf("re-append added %d entries, want 0", added)
	}
	doc, err := ReadProfileDoc("tool2")
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.ConfigDirs) != 1 {
		t.Errorf("expected 1 entry, got %d", len(doc.ConfigDirs))
	}
}

func TestAppendProfileEntries_UpgradeMode(t *testing.T) {
	withTempProfilesDir(t)

	// First pass: read-only.
	if _, err := AppendProfileEntries("tool3", []config.ConfigDirEntry{
		{Path: `/home/test/.config/tool3`, Mode: "ro", Source: "auto"},
	}); err != nil {
		t.Fatal(err)
	}
	// Second pass: upgrade to rw.
	added, err := AppendProfileEntries("tool3", []config.ConfigDirEntry{
		{Path: `/home/test/.config/tool3`, Mode: "rw", Source: "manual"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if added != 0 {
		t.Errorf("upgrade should not count as added, got %d", added)
	}
	doc, err := ReadProfileDoc("tool3")
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.ConfigDirs) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(doc.ConfigDirs))
	}
	if doc.ConfigDirs[0].Mode != "rw" {
		t.Errorf("mode = %q, want rw", doc.ConfigDirs[0].Mode)
	}
	if doc.ConfigDirs[0].Source != "manual" {
		t.Errorf("source = %q, want manual", doc.ConfigDirs[0].Source)
	}
}

func TestAppendProfileEntries_EmptyInputs(t *testing.T) {
	withTempProfilesDir(t)
	if added, err := AppendProfileEntries("tool4", nil); err != nil || added != 0 {
		t.Errorf("nil entries: added=%d err=%v", added, err)
	}
	if _, err := AppendProfileEntries("", []config.ConfigDirEntry{{Path: "x"}}); err == nil {
		t.Error("empty tool name should error")
	}
}
