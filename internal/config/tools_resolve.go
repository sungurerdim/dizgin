// SPDX-License-Identifier: MIT

package config

import (
	"os"
)

// splitDeps is the shared kernel for the six Default*/Explicit* dep methods.
// It returns two existence-filtered slices:
//   - defaultFiltered: paths from defaults that are not excluded by ExcludeDefaults.
//   - explicitFiltered: paths from explicit (profile-declared), existence-filtered unchanged.
func (t ToolDef) splitDeps(defaults []string, explicit []string) (defaultFiltered []string, explicitFiltered []string) {
	filtered := make([]string, 0, len(defaults))
	for _, p := range defaults {
		if !t.IsExcluded(p) {
			filtered = append(filtered, p)
		}
	}
	return existingPaths(expandPaths(filtered)), existingPaths(expandPaths(explicit))
}

// DefaultFilteredToolDeps returns the universal default tool_deps after applying
// ExcludeDefaults, existence-filtered. Backend safety filters (e.g. C:\Windows
// exclusion) still apply to these paths.
func (t ToolDef) DefaultFilteredToolDeps() []string {
	def, _ := t.splitDeps(DefaultToolDeps, nil)
	return def
}

// ExplicitToolDeps returns only the profile-declared tool_deps, existence-filtered.
// These originate from the profile YAML; backend safety filters (e.g. C:\Windows
// exclusion) do not apply to explicitly declared paths.
func (t ToolDef) ExplicitToolDeps() []string {
	_, exp := t.splitDeps(nil, t.ToolDeps)
	return exp
}

// DefaultFilteredLibDeps returns the runtime-derived default lib_deps after applying
// ExcludeDefaults, existence-filtered. Backend safety filters still apply.
func (t ToolDef) DefaultFilteredLibDeps() []string {
	def, _ := t.splitDeps(RuntimeLibDeps(t.Runtime), nil)
	return def
}

// ExplicitLibDeps returns only the profile-declared lib_deps (and deprecated
// runtime_dirs), existence-filtered. Backend safety filters do not apply.
func (t ToolDef) ExplicitLibDeps() []string {
	combined := append(append([]string{}, t.LibDeps...), t.RuntimeDirs...)
	_, exp := t.splitDeps(nil, combined)
	return exp
}

// DefaultFilteredToolchainDeps returns the universal default toolchain_deps after applying
// ExcludeDefaults, existence-filtered. Used for Force=false mounts (backend safety filters apply).
func (t ToolDef) DefaultFilteredToolchainDeps() []string {
	def, _ := t.splitDeps(DefaultToolchainDeps, nil)
	return def
}

// ExplicitToolchainDeps returns only the profile-declared toolchain_deps, existence-filtered.
// Mounted with Force=true so backend safety filters do not silently drop them.
func (t ToolDef) ExplicitToolchainDeps() []string {
	_, exp := t.splitDeps(nil, t.ToolchainDeps)
	return exp
}

// EffectiveToolDeps returns the merged R/W tool dependency paths:
// DefaultToolDeps + profile tool_deps, minus ExcludeDefaults entries,
// filtered to paths that exist on disk.
func (t ToolDef) EffectiveToolDeps() []string {
	def, exp := t.splitDeps(DefaultToolDeps, t.ToolDeps)
	return append(def, exp...)
}

// EffectiveLibDeps returns the merged R/O library dependency paths:
// RuntimeLibDeps(runtime) + profile lib_deps + deprecated runtime_dirs,
// minus ExcludeDefaults entries, filtered to paths that exist on disk.
func (t ToolDef) EffectiveLibDeps() []string {
	explicit := append(append([]string{}, t.LibDeps...), t.RuntimeDirs...) // backward compat
	def, exp := t.splitDeps(RuntimeLibDeps(t.Runtime), explicit)
	return append(def, exp...)
}

// EffectiveEnv returns the merged environment map: DefaultEnv first, then profile
// Env. Profile values override defaults for the same key.
// Keys listed in ExcludeDefaults are excluded from the defaults portion.
func (t ToolDef) EffectiveEnv() map[string]string {
	defaults := DefaultEnv
	result := make(map[string]string, len(defaults)+len(t.Env))
	for k, v := range defaults {
		if !t.IsExcluded(k) {
			result[k] = v
		}
	}
	for k, v := range t.Env {
		result[k] = v
	}
	return result
}

// EffectiveMCPDirs returns the merged R/W MCP server directory paths:
// DefaultMCPDirs + profile mcp_dirs, minus ExcludeDefaults entries,
// filtered to paths that exist on disk.
func (t ToolDef) EffectiveMCPDirs() []string {
	def, exp := t.splitDeps(DefaultMCPDirs, t.MCPDirs)
	return append(def, exp...)
}

// ExpandedConfigMounts returns the full config-dirs list with Path fields
// expanded (env vars, tilde). When ConfigDirMounts is populated, it wins;
// otherwise ConfigDirs is promoted to structured entries with Mode="rw"
// and Source="profile" to match the pre-refactor behaviour.
//
// The returned slice preserves ordering so that user-added paths (Source=auto
// or manual) appended at the bottom of the user-scope profile stay at the
// bottom of the mount list, making the mount table predictable.
func (t ToolDef) ExpandedConfigMounts() []ConfigDirEntry {
	if len(t.ConfigDirMounts) > 0 {
		home, _ := os.UserHomeDir()
		out := make([]ConfigDirEntry, 0, len(t.ConfigDirMounts))
		for _, e := range t.ConfigDirMounts {
			expanded := expandPath(e.Path, home)
			if expanded == "" {
				continue
			}
			e.Path = expanded
			if e.Mode == "" {
				e.Mode = "rw"
			}
			if e.Source == "" {
				e.Source = "profile"
			}
			out = append(out, e)
		}
		return out
	}
	// Fallback to the legacy string list.
	out := make([]ConfigDirEntry, 0, len(t.ConfigDirs))
	for _, p := range expandPaths(t.ConfigDirs) {
		out = append(out, ConfigDirEntry{
			Path:   p,
			Mode:   "rw",
			Source: "profile",
		})
	}
	return out
}
