// SPDX-License-Identifier: MIT

package depclosure

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// cacheEntry pins a binary's resolved direct dependencies to the exact
// file state (mtime + size) they were computed from. A package upgrade
// changes at least one of the two, which invalidates the entry
// automatically — no explicit cache-busting logic needed.
type cacheEntry struct {
	ModTime int64    `json:"mtime"`
	Size    int64    `json:"size"`
	Deps    []string `json:"deps"`
}

// depCache is a process-lifetime, mutex-guarded, disk-backed memo of
// parseDeps results. Without it, every session re-parses every executable
// in every PATH directory from scratch — measured on a real machine with
// a populated Homebrew bin/ (~300 executables): 2s wall time and ~210MB
// peak RSS for a session that otherwise completes in ~150ms and ~9MB.
// Binaries change only on a package upgrade, so the overwhelmingly common
// case (same tools as last session) should cost close to nothing.
type depCache struct {
	mu      sync.Mutex
	path    string
	entries map[string]cacheEntry
	dirty   bool
}

var (
	globalCache     *depCache
	globalCacheOnce sync.Once
)

func cachePath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, brand.DotDir, "cache", "depclosure.json")
}

func getCache() *depCache {
	globalCacheOnce.Do(func() {
		globalCache = loadCache(cachePath())
	})
	return globalCache
}

// loadCache reads path if it exists; a missing, corrupt, or unreadable
// cache file is treated as "empty" rather than an error — this is a pure
// optimization layer, never load-bearing for correctness.
func loadCache(path string) *depCache {
	c := &depCache{path: path, entries: make(map[string]cacheEntry)}
	if path == "" {
		return c
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return c
	}
	_ = json.Unmarshal(data, &c.entries) // best-effort; leaves entries empty on failure
	if c.entries == nil {
		c.entries = make(map[string]cacheEntry)
	}
	return c
}

// get returns the cached deps for path if the file's current mtime+size
// match what the cache entry was computed from.
func (c *depCache) get(path string, modTime int64, size int64) ([]string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[path]
	if !ok || e.ModTime != modTime || e.Size != size {
		return nil, false
	}
	return e.Deps, true
}

// put records path's freshly computed deps against its current file
// state. deps is never nil in the stored entry (an empty non-nil slice)
// so a binary with zero dependencies still gets a cache hit next time,
// rather than "not found" forcing a re-parse forever.
func (c *depCache) put(path string, modTime int64, size int64, deps []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if deps == nil {
		deps = []string{}
	}
	c.entries[path] = cacheEntry{ModTime: modTime, Size: size, Deps: deps}
	c.dirty = true
}

// save writes the cache to disk if anything changed since it was loaded.
// Atomic (temp file + rename) so a concurrent dizgin session reading the
// file never observes a partial write; last-writer-wins on the rare
// concurrent-session race is an acceptable loss for a pure optimization
// layer — never a correctness issue, since a lost update just means the
// next session re-parses that one binary.
//
// Prunes entries whose path no longer exists before writing: without
// this, every tool a user ever installs and later removes (a version
// upgrade via a package manager that changes paths, a one-off binary
// tried once) leaves a permanent, never-reclaimed entry — slow, unbounded
// growth over the life of the machine. The cache should track only what
// is currently installed, nothing that used to be.
func (c *depCache) save() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.dirty || c.path == "" {
		return
	}
	for path := range c.entries {
		if _, err := os.Stat(path); err != nil {
			delete(c.entries, path)
		}
	}
	data, err := json.Marshal(c.entries)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return
	}
	if os.Rename(tmp, c.path) == nil {
		c.dirty = false
	}
}
