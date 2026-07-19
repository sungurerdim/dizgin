// SPDX-License-Identifier: MIT

package depclosure

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDepCache_MissThenHit(t *testing.T) {
	c := loadCache(filepath.Join(t.TempDir(), "cache.json"))

	if _, ok := c.get("/bin/git", 100, 200); ok {
		t.Fatal("empty cache should miss")
	}
	c.put("/bin/git", 100, 200, []string{"/lib/a.dylib"})
	got, ok := c.get("/bin/git", 100, 200)
	if !ok {
		t.Fatal("expected hit after put")
	}
	if !reflect.DeepEqual(got, []string{"/lib/a.dylib"}) {
		t.Errorf("got %v", got)
	}
}

func TestDepCache_StaleMtimeMisses(t *testing.T) {
	c := loadCache(filepath.Join(t.TempDir(), "cache.json"))
	c.put("/bin/git", 100, 200, []string{"/lib/a.dylib"})

	if _, ok := c.get("/bin/git", 999, 200); ok {
		t.Error("changed mtime should miss, got a hit")
	}
	if _, ok := c.get("/bin/git", 100, 999); ok {
		t.Error("changed size should miss, got a hit")
	}
}

func TestDepCache_SaveThenLoadRoundTrips(t *testing.T) {
	// save() prunes entries for paths that no longer exist (see
	// TestDepCache_SavePrunesEntriesForDeletedFiles), so the round-trip
	// entry here must be a real file, not a placeholder path.
	realFile := filepath.Join(t.TempDir(), "somebinary")
	if err := os.WriteFile(realFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cache.json")
	c := loadCache(path)
	c.put(realFile, 100, 200, []string{"/lib/a.dylib", "/lib/b.dylib"})
	c.save()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("save() should have created %s: %v", path, err)
	}

	reloaded := loadCache(path)
	got, ok := reloaded.get(realFile, 100, 200)
	if !ok {
		t.Fatal("expected hit after reload from disk")
	}
	if !reflect.DeepEqual(got, []string{"/lib/a.dylib", "/lib/b.dylib"}) {
		t.Errorf("got %v", got)
	}
}

func TestDepCache_ZeroDepsStillCaches(t *testing.T) {
	// A binary with no dependencies (a static executable, say) must still
	// get a cache hit next time — otherwise it would be re-parsed on
	// every single session forever, the exact waste this cache exists to
	// eliminate.
	c := loadCache(filepath.Join(t.TempDir(), "cache.json"))
	c.put("/bin/true", 1, 2, nil)
	got, ok := c.get("/bin/true", 1, 2)
	if !ok {
		t.Fatal("expected hit for a zero-dependency entry")
	}
	if len(got) != 0 {
		t.Errorf("expected empty deps, got %v", got)
	}
}

func TestDepCache_SavePrunesEntriesForDeletedFiles(t *testing.T) {
	dir := t.TempDir()
	realFile := filepath.Join(dir, "still-here")
	if err := os.WriteFile(realFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	goneFile := filepath.Join(dir, "uninstalled-tool")

	path := filepath.Join(t.TempDir(), "cache.json")
	c := loadCache(path)
	c.put(realFile, 1, 2, []string{"/lib/a.dylib"})
	c.put(goneFile, 1, 2, []string{"/lib/b.dylib"}) // never actually created on disk
	c.save()

	reloaded := loadCache(path)
	if _, ok := reloaded.get(realFile, 1, 2); !ok {
		t.Error("entry for a file that still exists should survive save()")
	}
	if _, ok := reloaded.get(goneFile, 1, 2); ok {
		t.Error("entry for a nonexistent file should be pruned by save(), not persisted forever")
	}
}

func TestDepCache_SaveNoOpWhenNotDirty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	c := loadCache(path)
	c.save() // nothing written yet — must not create an empty file
	if _, err := os.Stat(path); err == nil {
		t.Error("save() with no changes should not create a file")
	}
}

func TestDepCache_MissingFileLoadsEmpty(t *testing.T) {
	c := loadCache(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if _, ok := c.get("/anything", 1, 2); ok {
		t.Error("a fresh cache with no backing file should miss everything")
	}
}

func TestDepCache_CorruptFileLoadsEmptyNotFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	if err := os.WriteFile(path, []byte("not valid json{{{"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := loadCache(path) // must not panic or error out
	if _, ok := c.get("/anything", 1, 2); ok {
		t.Error("a corrupt cache file should load as empty, not fabricate a hit")
	}
}

func TestCachedParseDeps_NonExistentPathBypassesCache(t *testing.T) {
	orig := parseDeps
	calls := 0
	parseDeps = func(path string) ([]string, error) {
		calls++
		return []string{"/fake/dep"}, nil
	}
	defer func() { parseDeps = orig }()

	c := loadCache(filepath.Join(t.TempDir(), "cache.json"))
	// "/no/such/path" fails os.Stat, so cachedParseDeps must fall back to
	// calling parseDeps directly rather than erroring out itself.
	deps, err := cachedParseDeps(c, "/no/such/path")
	if err != nil {
		t.Fatalf("cachedParseDeps: %v", err)
	}
	if !reflect.DeepEqual(deps, []string{"/fake/dep"}) {
		t.Errorf("deps = %v", deps)
	}
	if calls != 1 {
		t.Errorf("parseDeps should be called exactly once, got %d", calls)
	}
}

func TestCachedParseDeps_RealFileCachesAcrossCalls(t *testing.T) {
	orig := parseDeps
	calls := 0
	parseDeps = func(path string) ([]string, error) {
		calls++
		return []string{"/fake/dep"}, nil
	}
	defer func() { parseDeps = orig }()

	realFile := filepath.Join(t.TempDir(), "somebinary")
	if err := os.WriteFile(realFile, []byte("fake-binary-content"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := loadCache(filepath.Join(t.TempDir(), "cache.json"))

	if _, err := cachedParseDeps(c, realFile); err != nil {
		t.Fatal(err)
	}
	if _, err := cachedParseDeps(c, realFile); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("second call should be served from cache, parseDeps called %d times", calls)
	}
}
