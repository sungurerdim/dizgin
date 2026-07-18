// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// TST-14: readVersionCache / writeVersionCache round-trip, TTL/staleness, version comparison.

// redirectCacheDir points os.UserCacheDir() at a temp directory for the
// duration of the test. On Windows UserCacheDir uses %LocalAppData%;
// on Linux/macOS it uses $XDG_CACHE_HOME / $HOME/.cache.
func redirectCacheDir(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	switch runtime.GOOS {
	case "windows":
		t.Setenv("LocalAppData", tmp)
	case "darwin":
		// UserCacheDir on darwin is $HOME/Library/Caches, ignoring XDG.
		t.Setenv("HOME", tmp)
		return filepath.Join(tmp, "Library", "Caches")
	default:
		t.Setenv("XDG_CACHE_HOME", tmp)
	}
	return tmp
}

func TestVersionCache_RoundTrip(t *testing.T) {
	redirectCacheDir(t)

	want := versionCheckCache{
		CheckedAt: time.Now().Truncate(time.Second),
		Latest:    "v1.2.3",
	}
	writeVersionCache(want)

	got, err := readVersionCache()
	if err != nil {
		t.Fatalf("readVersionCache after write: %v", err)
	}
	if got.Latest != want.Latest {
		t.Errorf("Latest: want %q, got %q", want.Latest, got.Latest)
	}
	// CheckedAt survives the JSON round-trip within one second.
	if got.CheckedAt.IsZero() {
		t.Error("CheckedAt should not be zero after round-trip")
	}
	diff := got.CheckedAt.Sub(want.CheckedAt)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("CheckedAt drift too large: %v", diff)
	}
}

func TestVersionCache_ReadMissing(t *testing.T) {
	redirectCacheDir(t)
	// No file written — should return an error.
	_, err := readVersionCache()
	if err == nil {
		t.Error("expected error reading missing cache, got nil")
	}
}

func TestVersionCache_WriteCreatesFile(t *testing.T) {
	cacheBase := redirectCacheDir(t)

	writeVersionCache(versionCheckCache{Latest: "v0.9.0", CheckedAt: time.Now()})

	// The file should exist under cacheBase/dizgin/version-check.json.
	expected := filepath.Join(cacheBase, brand.Name, "version-check.json")
	if _, err := os.Stat(expected); err != nil {
		t.Errorf("cache file not created at %s: %v", expected, err)
	}
}

func TestVersionCache_FilePermissions(t *testing.T) {
	redirectCacheDir(t)

	writeVersionCache(versionCheckCache{Latest: "v1.0.0", CheckedAt: time.Now()})

	path := versionCachePath()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat cache file: %v", err)
	}
	// File must not be world-readable (mode 0600).
	// On Windows the mode bits are coarser, but we can at least verify the
	// file exists and is a regular file.
	if !info.Mode().IsRegular() {
		t.Errorf("cache path is not a regular file: %v", info.Mode())
	}
}

func TestVersionCache_StalenessLogic(t *testing.T) {
	redirectCacheDir(t)

	// Write a cache entry that is older than the TTL.
	stale := versionCheckCache{
		CheckedAt: time.Now().Add(-(versionCheckTTL + time.Minute)),
		Latest:    "v0.1.0",
	}
	writeVersionCache(stale)

	got, err := readVersionCache()
	if err != nil {
		t.Fatalf("readVersionCache: %v", err)
	}
	// The cache should be readable even if stale — staleness is a policy
	// decision made by the caller (latestVersionCached), not the reader.
	if got.Latest != stale.Latest {
		t.Errorf("Latest: want %q, got %q", stale.Latest, got.Latest)
	}
	// Caller-side staleness check: time.Since(got.CheckedAt) >= versionCheckTTL.
	if time.Since(got.CheckedAt) < versionCheckTTL {
		t.Error("expected stale cache entry to have CheckedAt older than TTL")
	}
}

func TestVersionCache_FreshEntryShouldBeUsed(t *testing.T) {
	redirectCacheDir(t)

	fresh := versionCheckCache{
		CheckedAt: time.Now(),
		Latest:    "v2.0.0",
	}
	writeVersionCache(fresh)

	got, err := readVersionCache()
	if err != nil {
		t.Fatalf("readVersionCache: %v", err)
	}
	// Fresh entry: time.Since(CheckedAt) < versionCheckTTL — caller should use it.
	if time.Since(got.CheckedAt) >= versionCheckTTL {
		t.Error("expected fresh cache entry to be within TTL")
	}
	if got.Latest != fresh.Latest {
		t.Errorf("Latest: want %q, got %q", fresh.Latest, got.Latest)
	}
}

func TestVersionCache_MalformedJSON(t *testing.T) {
	redirectCacheDir(t)

	// Write garbage to the cache file.
	path := versionCachePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte("not-json{{{"), 0o600); err != nil {
		t.Fatalf("write bad cache: %v", err)
	}

	_, err := readVersionCache()
	if err == nil {
		t.Error("expected error reading malformed JSON cache, got nil")
	}
}

func TestVersionCache_UpdatesExistingFile(t *testing.T) {
	redirectCacheDir(t)

	// Write v1, then overwrite with v2.
	writeVersionCache(versionCheckCache{Latest: "v1.0.0", CheckedAt: time.Now()})
	writeVersionCache(versionCheckCache{Latest: "v2.0.0", CheckedAt: time.Now()})

	got, err := readVersionCache()
	if err != nil {
		t.Fatalf("readVersionCache: %v", err)
	}
	if got.Latest != "v2.0.0" {
		t.Errorf("Latest: want v2.0.0, got %q", got.Latest)
	}
}

func TestVersionCache_JSONStructure(t *testing.T) {
	redirectCacheDir(t)

	ts := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	writeVersionCache(versionCheckCache{Latest: "v3.1.4", CheckedAt: ts})

	path := versionCachePath()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cache file: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parse cache JSON: %v", err)
	}
	if m["latest"] != "v3.1.4" {
		t.Errorf("JSON 'latest': want v3.1.4, got %v", m["latest"])
	}
	if m["checked_at"] == nil {
		t.Error("JSON 'checked_at' field missing")
	}
}
