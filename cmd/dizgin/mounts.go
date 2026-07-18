// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/config"
	"github.com/sungurerdim/dizgin/internal/sandbox"
	"github.com/sungurerdim/dizgin/internal/security"
)

// sanitizeMountPath validates and cleans a mount path. Returns empty
// string if the cleaned path contains ".." (traversal attempt).
func sanitizeMountPath(p string) string {
	cleaned := filepath.Clean(p)
	if slices.Contains(strings.Split(cleaned, string(filepath.Separator)), "..") {
		fmt.Fprintf(os.Stderr, brand.Name+": mount path %q contains path traversal, skipping\n", p)
		return ""
	}
	return cleaned
}

// mountAppender tracks duplicates across multiple addX helpers so the
// classifier never sees two entries for the same host path (one as RW
// from config_dirs, another as RO from a host PATH dir, etc.). Duplicate
// resolution: the most-permissive request wins (RW overrides RO) and
// the strongest category survives (Workdir > DeclaredRW > DeclaredRO >
// Path > System).
type mountAppender struct {
	mounts []sandbox.Mount
	seen   map[string]int // case-insensitive cleaned host path → index in mounts
}

func newMountAppender(estCap int) *mountAppender {
	return &mountAppender{
		mounts: make([]sandbox.Mount, 0, estCap),
		seen:   make(map[string]int, estCap),
	}
}

func (m *mountAppender) result() []sandbox.Mount { return m.mounts }

// add validates host, stat-checks it, then appends a Mount or merges
// with an existing entry for the same path. category and readOnly
// describe the declared intent; existence is checked here so callers do
// not have to guard each invocation.
func (m *mountAppender) add(host string, readOnly bool, category sandbox.MountCategory) {
	if host == "" {
		return
	}
	host = sanitizeMountPath(host)
	if host == "" {
		return
	}
	if _, err := os.Stat(host); err != nil {
		return
	}
	m.upsert(host, readOnly, category)
}

// addUnchecked appends host without stat-checking it. Used for the
// load-bearing workdir + tool-binary directory entries where the caller
// (resolveSession) has already validated existence. Without this the
// stat filter would silently drop the workdir when callers pass a
// not-yet-mkdir'd directory and produce a malformed mount list.
func (m *mountAppender) addUnchecked(host string, readOnly bool, category sandbox.MountCategory) {
	if host == "" {
		return
	}
	host = sanitizeMountPath(host)
	if host == "" {
		return
	}
	m.upsert(host, readOnly, category)
}

func (m *mountAppender) upsert(host string, readOnly bool, category sandbox.MountCategory) {
	key := strings.ToLower(host)
	if idx, ok := m.seen[key]; ok {
		existing := m.mounts[idx]
		if !readOnly && existing.ReadOnly {
			existing.ReadOnly = false
		}
		if category.Rank() > existing.Category.Rank() {
			existing.Category = category
		}
		m.mounts[idx] = existing
		return
	}
	m.seen[key] = len(m.mounts)
	m.mounts = append(m.mounts, sandbox.Mount{
		Host:     host,
		Guest:    host,
		ReadOnly: readOnly,
		Category: category,
	})
}

// buildMounts is the entry point session.go calls to construct the
// per-session mount list. The classifier in the appcontainer backend
// reads the Category tag on each Mount to decide stamping; the host
// path / guest path are identical (host_path == guest_path is the R2
// native-experience contract).
func buildMounts(wd string, def config.ToolDef, toolPath string) []sandbox.Mount {
	m := newMountAppender(32)

	// R1-A — workdir is always RW. Unchecked because resolveSession
	// already validated existence; the stat filter is only meant to
	// drop stale auto-discovered entries.
	m.addUnchecked(wd, false, sandbox.CategoryWorkdir)

	// Tool binary directory: read-only system path (typically Program
	// Files / inbox System32 / user toolchain install). Classified as
	// DeclaredRO so the classifier knows to stamp it RX when needed;
	// when it sits under an OS-managed root the inbox grant covers it.
	if toolPath != "" {
		binDir := filepath.Dir(toolPath)
		if binDir != "" && binDir != "." {
			cat := sandbox.CategoryDeclaredRO
			if security.IsSystemPath(binDir) {
				cat = sandbox.CategorySystem
			}
			m.addUnchecked(binDir, true, cat)
		}
	}

	addConfigDirMounts(m, def)
	addToolDepMounts(m, def)
	addLibDepMounts(m, def)
	addToolchainDepMounts(m, def)
	addNPMCacheMounts(m, def)
	addMCPDirMounts(m, def)
	addHostPathMounts(m)
	return m.result()
}

// addConfigDirMounts adds the user-config trees the tool wrote itself
// (~/.claude, ~/.cursor, etc.). Always R1-B / DeclaredRW because tools
// expect to write back into their config dirs (token refresh, state).
func addConfigDirMounts(m *mountAppender, def config.ToolDef) {
	for _, entry := range def.ExpandedConfigMounts() {
		m.add(entry.Path, entry.ReadOnly(), sandbox.CategoryDeclaredRW)
	}
}

// addToolDepMounts splits explicit vs default tool_deps. Explicit
// entries are user-declared so they classify as DeclaredRW (the
// classifier stamps them with the per-session AC SID). Default entries
// (auto-discovered ~/go etc.) classify the same way — the prior
// "default vs explicit" Force distinction was a backend safety filter,
// which the 3-tier classifier replaces entirely.
func addToolDepMounts(m *mountAppender, def config.ToolDef) {
	for _, d := range def.DefaultFilteredToolDeps() {
		m.add(d, false, sandbox.CategoryDeclaredRW)
	}
	for _, d := range def.ExplicitToolDeps() {
		m.add(d, false, sandbox.CategoryDeclaredRW)
	}
}

// addLibDepMounts adds shared library directories — runtime DLL closures
// for Node.js / Python / etc. Always read-only. R1-C / DeclaredRO so the
// classifier stamps them with FILE_TRAVERSE + FILE_GENERIC_READ (RX
// equivalent without execute) and junction follow stays disabled.
func addLibDepMounts(m *mountAppender, def config.ToolDef) {
	for _, d := range def.DefaultFilteredLibDeps() {
		m.add(d, true, sandbox.CategoryDeclaredRO)
	}
	for _, d := range def.ExplicitLibDeps() {
		m.add(d, true, sandbox.CategoryDeclaredRO)
	}
}

// addMCPDirMounts adds MCP server directories — always RW so MCP
// servers can mutate their local state (~/.mcp logs etc.). R1-B.
func addMCPDirMounts(m *mountAppender, def config.ToolDef) {
	for _, d := range def.EffectiveMCPDirs() {
		m.add(d, false, sandbox.CategoryDeclaredRW)
	}
}

// addNPMCacheMounts adds the npm cache when the tool's runtime indicates
// it needs one (Node / Bun). RW because npm writes the cache mid-tool.
func addNPMCacheMounts(m *mountAppender, def config.ToolDef) {
	if !def.NeedsNPMCache() {
		return
	}
	npmCache := config.NPMCacheDir()
	if npmCache == "" {
		return
	}
	m.add(npmCache, false, sandbox.CategoryDeclaredRW)
}

// addToolchainDepMounts mounts ~/.cargo, ~/.rustup, GOPATH etc. — RW
// because toolchains write to their caches during normal operation
// (module downloads, build artifacts). R1-B / DeclaredRW.
func addToolchainDepMounts(m *mountAppender, def config.ToolDef) {
	for _, d := range def.DefaultFilteredToolchainDeps() {
		m.add(d, false, sandbox.CategoryDeclaredRW)
	}
	for _, d := range def.ExplicitToolchainDeps() {
		m.add(d, false, sandbox.CategoryDeclaredRW)
	}
	for _, d := range config.EnvDirDeps() {
		m.add(d, false, sandbox.CategoryDeclaredRW)
	}
}

// addHostPathMounts adds every absolute directory listed in $PATH so
// sub-processes the tool spawns can locate themselves. Read-only.
// Entries under OS-managed roots are tagged CategorySystem (inbox AC
// RX grant covers them); others are CategoryPath (also covered by
// inbox, but the tag lets the classifier distinguish them in audit
// logs and a future per-user PATH allowlist).
//
// DIZGIN_DISABLE_PATH_MOUNTS=1 disables this expansion entirely — useful
// for minimal smoke tests that don't want to pay the enumerate cost.
func addHostPathMounts(m *mountAppender) {
	if os.Getenv(brand.Env("DISABLE_PATH_MOUNTS")) == "1" {
		return
	}
	skipDirs := make(map[string]bool, 4)
	for _, env := range []string{"TEMP", "TMP", "TMPDIR"} {
		if v := os.Getenv(env); v != "" {
			skipDirs[strings.ToLower(filepath.Clean(v))] = true
		}
	}

	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		dir = sanitizeMountPath(dir)
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		if skipDirs[strings.ToLower(dir)] {
			continue
		}
		cat := sandbox.CategoryPath
		if security.IsSystemPath(dir) {
			cat = sandbox.CategorySystem
		}
		m.add(dir, true, cat)
	}
}
