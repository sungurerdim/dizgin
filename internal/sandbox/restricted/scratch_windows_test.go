// SPDX-License-Identifier: MIT

//go:build windows

package restricted

// TST-11 — ScratchRoots root-selection logic and SessionScratchDir path
// construction. The actual MkdirAll calls are tested; env-override of
// LOCALAPPDATA is exercised via t.Setenv so the live filesystem acts as
// the check fixture (real OS paths, no mocks).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// ---- ScratchRoots ----

func TestScratchRoots_AlwaysIncludesProgramData(t *testing.T) {
	roots := ScratchRoots()
	if len(roots) == 0 {
		t.Fatal("ScratchRoots must return at least one entry")
	}
	first := roots[0]
	// The first candidate must be under C:\ProgramData regardless of env.
	if !strings.EqualFold(first, `C:\ProgramData\dizgin\restricted`) {
		t.Errorf("first root should be C:\\ProgramData\\dizgin\\restricted; got %q", first)
	}
}

func TestScratchRoots_WithLOCALAPPDATA(t *testing.T) {
	fakeLA := `C:\Users\testuser\AppData\Local`
	t.Setenv("LOCALAPPDATA", fakeLA)

	roots := ScratchRoots()
	if len(roots) < 2 {
		t.Fatalf("expected at least 2 roots when LOCALAPPDATA is set; got %d: %v", len(roots), roots)
	}
	want := filepath.Join(fakeLA, brand.Name, "restricted")
	found := false
	for _, r := range roots[1:] {
		if strings.EqualFold(r, want) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("LOCALAPPDATA-derived root %q not in %v", want, roots)
	}
}

func TestScratchRoots_EmptyLOCALAPPDATA_OnlyProgramData(t *testing.T) {
	t.Setenv("LOCALAPPDATA", "")

	roots := ScratchRoots()
	// When LOCALAPPDATA is empty the fallback must not be appended.
	for _, r := range roots {
		low := strings.ToLower(r)
		if strings.Contains(low, "localappdata") ||
			strings.HasPrefix(low, strings.ToLower(os.TempDir())) {
			t.Errorf("scratch root %q looks LOCALAPPDATA/temp-derived when LOCALAPPDATA is empty", r)
		}
	}
	// At minimum, ProgramData root must be present.
	if len(roots) == 0 || !strings.EqualFold(roots[0], `C:\ProgramData\dizgin\restricted`) {
		t.Errorf("with empty LOCALAPPDATA, roots[0] must be ProgramData; got %v", roots)
	}
	// Should not have an invalid second entry derived from empty LOCALAPPDATA.
	for _, r := range roots[1:] {
		if strings.HasPrefix(r, string(filepath.Separator)) || r == filepath.Join("", brand.Name, "restricted") {
			t.Errorf("invalid root derived from empty LOCALAPPDATA: %q", r)
		}
	}
}

// ---- SessionScratchDir path construction ----

func TestSessionScratchDir_PathContainsSessionID(t *testing.T) {
	// Use LOCALAPPDATA so the test stays writable without elevation.
	fakeLA := t.TempDir()
	t.Setenv("LOCALAPPDATA", fakeLA)
	// Clear ProgramData to force use of LOCALAPPDATA fallback (ProgramData
	// is typically admin-owned; the test runner may not be elevated).
	// We override by pointing a writable temp dir at LOCALAPPDATA only —
	// SessionScratchDir tries roots in order; it will succeed on LOCALAPPDATA
	// when ProgramData mkdir fails (no elevation in CI).

	sessionID := "test-session-abc123"
	dir, err := SessionScratchDir(sessionID)
	if err != nil {
		t.Fatalf("SessionScratchDir(%q): %v", sessionID, err)
	}
	if !strings.HasSuffix(dir, sessionID) {
		t.Errorf("expected dir to end with sessionID %q; got %q", sessionID, dir)
	}
	// Verify the directory was actually created.
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("SessionScratchDir returned %q but it doesn't exist on disk: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
}

func TestSessionScratchDir_DifferentSessionsGetDifferentPaths(t *testing.T) {
	fakeLA := t.TempDir()
	t.Setenv("LOCALAPPDATA", fakeLA)

	ids := []string{
		"session-alpha-001",
		"session-beta-002",
		"session-gamma-003",
	}
	seen := make(map[string]bool)
	for _, id := range ids {
		dir, err := SessionScratchDir(id)
		if err != nil {
			t.Fatalf("SessionScratchDir(%q): %v", id, err)
		}
		if seen[dir] {
			t.Errorf("duplicate scratch dir %q for different session IDs", dir)
		}
		seen[dir] = true
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
	}
}

func TestSessionScratchDir_NestedUnderRestrictedSubdir(t *testing.T) {
	fakeLA := t.TempDir()
	t.Setenv("LOCALAPPDATA", fakeLA)

	dir, err := SessionScratchDir("my-session-xyz")
	if err != nil {
		t.Fatalf("SessionScratchDir: %v", err)
	}
	// The path must include the "restricted" segment so the orphan-sweeper
	// can glob across backends without cross-backend collisions.
	if !strings.Contains(strings.ToLower(dir), "restricted") {
		t.Errorf("scratch dir %q must contain 'restricted' segment for sweeper compat", dir)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
}

func TestSessionScratchDir_IdempotentOnExisting(t *testing.T) {
	fakeLA := t.TempDir()
	t.Setenv("LOCALAPPDATA", fakeLA)

	const id = "idempotent-session"
	dir1, err := SessionScratchDir(id)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	dir2, err := SessionScratchDir(id)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if dir1 != dir2 {
		t.Errorf("idempotency broken: first=%q second=%q", dir1, dir2)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir1) })
}
