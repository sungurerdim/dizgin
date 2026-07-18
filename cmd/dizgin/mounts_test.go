// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/sandbox"
)

// TST-19: addHostPathMounts boundary tests.

// hostPaths extracts the host-path strings from a mount list.
func hostPaths(mounts []sandbox.Mount) []string {
	out := make([]string, 0, len(mounts))
	for _, m := range mounts {
		out = append(out, m.Host)
	}
	return out
}

// containsPath reports whether host appears in the mount list (case-insensitive
// on Windows because the mountAppender canonicalises to lowercase).
func containsPath(mounts []sandbox.Mount, host string) bool {
	lower := strings.ToLower(filepath.Clean(host))
	for _, m := range mounts {
		if strings.ToLower(m.Host) == lower {
			return true
		}
	}
	return false
}

func TestAddHostPathMounts_EmptyPATH(t *testing.T) {
	t.Setenv(brand.Env("DISABLE_PATH_MOUNTS"), "")
	t.Setenv("PATH", "")
	t.Setenv("TEMP", "")
	t.Setenv("TMP", "")
	t.Setenv("TMPDIR", "")

	m := newMountAppender(4)
	addHostPathMounts(m)

	// No PATH entries means no path mounts added.
	if len(m.result()) != 0 {
		t.Errorf("empty PATH: want 0 path mounts, got %d: %v", len(m.result()), hostPaths(m.result()))
	}
}

func TestAddHostPathMounts_DisableEnvSkipsAll(t *testing.T) {
	// Allocate temp dir before clearing TEMP so t.TempDir() uses the real OS temp.
	dir := t.TempDir()

	t.Setenv(brand.Env("DISABLE_PATH_MOUNTS"), "1")
	t.Setenv("PATH", dir)
	t.Setenv("TEMP", "")
	t.Setenv("TMP", "")
	t.Setenv("TMPDIR", "")

	m := newMountAppender(4)
	addHostPathMounts(m)

	if len(m.result()) != 0 {
		t.Errorf("DIZGIN_DISABLE_PATH_MOUNTS=1: want 0 mounts, got %d", len(m.result()))
	}
}

func TestAddHostPathMounts_SingleEntryAdded(t *testing.T) {
	// Allocate temp dir BEFORE clearing TEMP/TMP so os.TempDir() is still valid.
	dir := t.TempDir()

	t.Setenv(brand.Env("DISABLE_PATH_MOUNTS"), "")
	t.Setenv("TEMP", "")
	t.Setenv("TMP", "")
	t.Setenv("TMPDIR", "")
	t.Setenv("PATH", dir)

	m := newMountAppender(4)
	addHostPathMounts(m)

	if !containsPath(m.result(), dir) {
		t.Errorf("expected %q in path mounts, got: %v", dir, hostPaths(m.result()))
	}
	// PATH mounts are always read-only.
	lowerDir := strings.ToLower(filepath.Clean(dir))
	for _, mount := range m.result() {
		if strings.ToLower(mount.Host) == lowerDir {
			if !mount.ReadOnly {
				t.Errorf("PATH mount for %q should be read-only", dir)
			}
		}
	}
}

func TestAddHostPathMounts_DuplicatesDeduped(t *testing.T) {
	// Allocate temp dir BEFORE clearing TEMP/TMP.
	dir := t.TempDir()

	t.Setenv(brand.Env("DISABLE_PATH_MOUNTS"), "")
	t.Setenv("TEMP", "")
	t.Setenv("TMP", "")
	t.Setenv("TMPDIR", "")

	// Put the same directory in PATH twice.
	pathVal := dir + string(os.PathListSeparator) + dir
	t.Setenv("PATH", pathVal)

	m := newMountAppender(4)
	addHostPathMounts(m)

	count := 0
	lowerDir := strings.ToLower(filepath.Clean(dir))
	for _, mount := range m.result() {
		if strings.ToLower(mount.Host) == lowerDir {
			count++
		}
	}
	if count != 1 {
		t.Errorf("duplicate PATH entry: want 1 mount for %q, got %d", dir, count)
	}
}

func TestAddHostPathMounts_MultipleDistinctEntries(t *testing.T) {
	// Allocate temp dirs BEFORE clearing TEMP/TMP.
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	t.Setenv(brand.Env("DISABLE_PATH_MOUNTS"), "")
	t.Setenv("TEMP", "")
	t.Setenv("TMP", "")
	t.Setenv("TMPDIR", "")

	pathVal := dir1 + string(os.PathListSeparator) + dir2
	t.Setenv("PATH", pathVal)

	m := newMountAppender(4)
	addHostPathMounts(m)

	if !containsPath(m.result(), dir1) {
		t.Errorf("expected %q in path mounts", dir1)
	}
	if !containsPath(m.result(), dir2) {
		t.Errorf("expected %q in path mounts", dir2)
	}
}

func TestAddHostPathMounts_NonExistentDirSkipped(t *testing.T) {
	// Allocate temp dir BEFORE clearing TEMP/TMP.
	base := t.TempDir()

	t.Setenv(brand.Env("DISABLE_PATH_MOUNTS"), "")
	t.Setenv("TEMP", "")
	t.Setenv("TMP", "")
	t.Setenv("TMPDIR", "")

	// Use a path guaranteed not to exist.
	ghost := filepath.Join(base, "nonexistent-subdir-xyz")
	t.Setenv("PATH", ghost)

	m := newMountAppender(4)
	addHostPathMounts(m)

	if containsPath(m.result(), ghost) {
		t.Errorf("nonexistent PATH dir should be skipped, but was included")
	}
}

func TestAddHostPathMounts_TempDirSkipped(t *testing.T) {
	// Allocate temp dir BEFORE setting TEMP= to that dir.
	tmpDir := t.TempDir()

	t.Setenv(brand.Env("DISABLE_PATH_MOUNTS"), "")
	t.Setenv("TEMP", tmpDir)
	t.Setenv("TMP", "")
	t.Setenv("TMPDIR", "")
	t.Setenv("PATH", tmpDir)

	m := newMountAppender(4)
	addHostPathMounts(m)

	if containsPath(m.result(), tmpDir) {
		t.Errorf("TEMP dir %q should be skipped from PATH mounts", tmpDir)
	}
}

// ── mountAppender dedup semantics ─────────────────────────────────────────────

func TestMountAppender_RWBeatsRO(t *testing.T) {
	dir := t.TempDir()
	m := newMountAppender(2)
	// Add as RO first, then RW — RW should win.
	m.addUnchecked(dir, true, sandbox.CategoryDeclaredRO)
	m.addUnchecked(dir, false, sandbox.CategoryDeclaredRW)

	result := m.result()
	if len(result) != 1 {
		t.Fatalf("want 1 mount, got %d", len(result))
	}
	if result[0].ReadOnly {
		t.Error("RW should override RO for the same path")
	}
}

func TestMountAppender_HigherCategoryWins(t *testing.T) {
	dir := t.TempDir()
	m := newMountAppender(2)
	// Rank order (highest first): Workdir=5, DeclaredRW=4, DeclaredRO=3, Path=2, System=1.
	// Add System first (rank 1), then DeclaredRO (rank 3) — DeclaredRO should win.
	m.addUnchecked(dir, true, sandbox.CategorySystem)
	m.addUnchecked(dir, true, sandbox.CategoryDeclaredRO)

	result := m.result()
	if len(result) != 1 {
		t.Fatalf("want 1 mount, got %d", len(result))
	}
	if result[0].Category != sandbox.CategoryDeclaredRO {
		t.Errorf("category: want DeclaredRO (rank 3 > System rank 1), got %v", result[0].Category)
	}
}

func TestMountAppender_CaseInsensitiveDedupOnWindows(t *testing.T) {
	if os.PathSeparator != '\\' {
		t.Skip("case-insensitive dedup is only relevant on Windows")
	}
	dir := t.TempDir()
	upper := strings.ToUpper(dir)

	m := newMountAppender(2)
	m.addUnchecked(dir, true, sandbox.CategoryPath)
	m.addUnchecked(upper, true, sandbox.CategoryPath)

	if len(m.result()) != 1 {
		t.Errorf("case-insensitive dedup: want 1 mount, got %d: %v",
			len(m.result()), hostPaths(m.result()))
	}
}
