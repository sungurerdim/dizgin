// SPDX-License-Identifier: MIT

//go:build darwin

package depclosure

import (
	"debug/macho"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func init() {
	parseDeps = parseMachODeps
}

// nativeCPU maps runtime.GOARCH to the Mach-O Cpu constant so a fat
// (universal) binary picks the slice that actually matches this process —
// parsing the wrong slice's load commands would resolve @rpath entries
// against the wrong architecture's rpath list.
func nativeCPU() macho.Cpu {
	if runtime.GOARCH == "arm64" {
		return macho.CpuArm64
	}
	return macho.CpuAmd64
}

// openNative opens binPath and returns the macho.File matching this
// process's architecture, transparently handling both thin and fat
// (universal) Mach-O binaries. The returned closer must be called by the
// caller once done.
func openNative(binPath string) (*macho.File, func(), error) {
	if fat, ferr := macho.OpenFat(binPath); ferr == nil {
		for _, arch := range fat.Arches {
			if arch.Cpu == nativeCPU() {
				return arch.File, func() { fat.Close() }, nil
			}
		}
		if len(fat.Arches) > 0 {
			// No exact arch match (unusual — e.g. an arm64e-only slice
			// on an arm64 host): fall back to the first slice rather
			// than giving up. Dependency paths live in the same
			// shared-library tree regardless of which slice's load
			// commands we read.
			return fat.Arches[0].File, func() { fat.Close() }, nil
		}
		fat.Close()
		return nil, nil, macho.ErrNotFat
	}
	// Not a fat binary (or unreadable as one) — try it as a thin Mach-O.
	// Any failure here (including a genuinely unreadable/missing file) is
	// reported as-is; the caller treats every error the same way (skip).
	f, err := macho.Open(binPath)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}

// parseMachODeps returns the resolved, on-disk dependency file paths that
// binPath's Mach-O load commands reference (LC_LOAD_DYLIB,
// LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB), with @rpath / @loader_path /
// @executable_path tokens resolved against the binary's own LC_RPATH
// entries and containing directory.
//
// A dependency that resolves to no on-disk file is skipped, not erred:
// this is the normal case for core system libraries (libSystem.B.dylib
// and friends) that exist ONLY inside dyld's shared cache on modern macOS
// — there is nothing to mount because dyld never touches a real file for
// them, and the base Seatbelt profile's broad /usr + /System allows
// already cover anything that *is* on disk under those roots.
func parseMachODeps(binPath string) ([]string, error) {
	f, closeFn, err := openNative(binPath)
	if err != nil {
		return nil, err
	}
	defer closeFn()

	binDir := filepath.Dir(binPath)
	var rpaths []string
	for _, l := range f.Loads {
		if r, ok := l.(*macho.Rpath); ok {
			rpaths = append(rpaths, resolveTokens(r.Path, binDir, nil))
		}
	}

	var deps []string
	for _, l := range f.Loads {
		d, ok := l.(*macho.Dylib)
		if !ok {
			continue
		}
		resolved := resolveDylib(d.Name, binDir, rpaths)
		if resolved == "" {
			continue
		}
		deps = append(deps, resolved)
	}
	return deps, nil
}

// resolveDylib turns a load command's declared name into an absolute,
// on-disk file path, or "" if none exists. name may be a plain absolute
// path, or carry an @rpath/@loader_path/@executable_path token that must
// be resolved against binDir and the binary's own rpath list.
func resolveDylib(name, binDir string, rpaths []string) string {
	if strings.HasPrefix(name, "@rpath/") {
		suffix := strings.TrimPrefix(name, "@rpath/")
		for _, rp := range rpaths {
			candidate := filepath.Join(rp, suffix)
			if fileExists(candidate) {
				return candidate
			}
		}
		return ""
	}
	resolved := resolveTokens(name, binDir, rpaths)
	if fileExists(resolved) {
		return resolved
	}
	return ""
}

// resolveTokens expands @loader_path and @executable_path against binDir
// (both mean "the directory containing this binary" for our purposes —
// dizgin never mounts a binary as a standalone bundle executable, so the
// executable_path/loader_path distinction that matters inside an .app
// bundle collapses to the same directory here). @rpath is intentionally
// NOT handled here (resolveDylib handles it against the full rpath list);
// this helper is also reused to clean a raw LC_RPATH entry that itself
// contains @loader_path/@executable_path.
func resolveTokens(path, binDir string, _ []string) string {
	path = strings.ReplaceAll(path, "@loader_path", binDir)
	path = strings.ReplaceAll(path, "@executable_path", binDir)
	if !filepath.IsAbs(path) {
		return filepath.Join(binDir, path)
	}
	return filepath.Clean(path)
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
