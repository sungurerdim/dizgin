// SPDX-License-Identifier: MIT

// Package depclosure dynamically resolves the shared-library dependency
// closure of a binary (and, transitively, of every library that binary
// itself loads) by parsing the binary's real load commands — Mach-O
// LC_LOAD_DYLIB / LC_RPATH on Darwin (internal/depclosure/macho_darwin.go),
// with an ELF/DT_NEEDED backend deferred to a later pass on Linux
// (depclosure_other.go no-ops there today).
//
// This replaces per-tool guesswork: instead of a hand-authored profile
// enumerating "Homebrew's pcre2 lib lives at /opt/homebrew/opt/pcre2/lib",
// dizgin asks the binary itself what it actually links against and mounts
// exactly those files, read-only, nothing more. It is the dynamic
// counterpart to the static lib_deps/tool_deps profile fields and to
// config.RuntimeLibDeps — those still apply for cases a link-time closure
// cannot see (e.g. a runtime dlopen()'d plugin), this covers everything a
// binary's own load commands declare.
//
// Minimal privilege by construction: callers get back individual resolved
// file paths, not directories, so a Homebrew/MacPorts/Nix package's other
// (unrelated) files under the same directory stay unreachable — only the
// specific library file a binary actually references is exposed.
package depclosure

import (
	"os"
	"path/filepath"
	"time"
)

// Limits bound the worst case of a pathological or maliciously crafted
// binary (thousands of fake load commands, or a dependency cycle) so
// resolution can never meaningfully delay session startup or exhaust
// memory. Mirrors the existing aggregate-deadline pattern used for the
// process-tree BFS in internal/monitor.
const (
	maxNodes    = 2000
	maxDepth    = 8
	walkTimeout = 3 * time.Second
)

// parseDeps is implemented per-OS: macho_darwin.go on Darwin,
// depclosure_other.go (no-op) everywhere else. It returns the absolute,
// on-disk, existing file paths that binPath's own load commands
// reference — not yet recursed into.
var parseDeps func(binPath string) ([]string, error)

// Resolve returns the deduplicated set of on-disk library files that seeds
// depend on, transitively, up to maxDepth/maxNodes/walkTimeout. Seeds
// themselves are never included in the result (callers already have their
// own mount for those). A seed that isn't a binary format parseDeps
// understands (a shell script, a non-existent path, a directory) is
// skipped silently — this is expected for the common case of scanning
// every file in a PATH directory, most of which are not the platform's
// native binary format.
func Resolve(seeds []string) []string {
	if parseDeps == nil {
		return nil
	}
	visited := make(map[string]bool, len(seeds)*4)
	var closure []string
	type queued struct {
		path  string
		depth int
	}
	queue := make([]queued, 0, len(seeds))
	for _, s := range seeds {
		if clean, err := filepath.Abs(s); err == nil {
			queue = append(queue, queued{path: clean, depth: 0})
		}
	}
	for _, s := range queue {
		visited[s.path] = true // seeds excluded from the result themselves
	}

	cache := getCache()
	deadline := time.Now().Add(walkTimeout)
	for len(queue) > 0 {
		if time.Now().After(deadline) || len(visited) > maxNodes {
			break
		}
		item := queue[0]
		queue = queue[1:]

		deps, err := cachedParseDeps(cache, item.path)
		if err != nil {
			continue // not this platform's binary format, or unreadable — skip
		}
		for _, d := range deps {
			if visited[d] {
				continue
			}
			visited[d] = true
			closure = append(closure, d)
			if item.depth+1 <= maxDepth {
				queue = append(queue, queued{path: d, depth: item.depth + 1})
			}
		}
	}
	cache.save()
	return closure
}

// cachedParseDeps wraps parseDeps with the on-disk depCache: a hit whose
// recorded mtime+size still match the file's current state skips the
// (comparatively expensive) binary-format parse entirely. A single
// os.Stat is paid either way — cheap relative to opening and parsing the
// file, and needed regardless to detect staleness. A stat failure falls
// back to calling parseDeps directly uncached rather than erroring here:
// parseDeps (or, in tests, a fake graph keyed on synthetic paths) is the
// authority on whether path is resolvable, not this cache layer.
func cachedParseDeps(cache *depCache, path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return parseDeps(path)
	}
	modTime := info.ModTime().UnixNano()
	size := info.Size()
	if deps, ok := cache.get(path, modTime, size); ok {
		return deps, nil
	}
	deps, err := parseDeps(path)
	if err != nil {
		return nil, err
	}
	cache.put(path, modTime, size, deps)
	return deps, nil
}

// ExecutablesIn lists the regular, executable files directly inside dir
// (non-recursive — PATH directories are conventionally flat). Used by
// callers that want to seed Resolve with "every subprocess this tool might
// spawn" rather than just the tool's own binary.
func ExecutablesIn(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil || info.Mode()&0o111 == 0 {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	return out
}
