// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// profileRegistry holds tool profiles loaded from YAML files and the built-in
// fallback registry. Populated by LoadProfiles() at startup.
var profileRegistry = map[string]ToolDef{}

// builtinTools is intentionally empty. All tool definitions live in
// profiles/*.yaml (SSOT). These are loaded by LoadProfiles() at startup
// from both embedded and on-disk profile directories.
var builtinTools = map[string]ToolDef{}

// SetProfiles replaces the profile registry (called by LoadProfiles).
func SetProfiles(profiles map[string]ToolDef) {
	profileRegistry = profiles
}

// LookupTool resolves a tool definition by name.
// Search order: profile registry → built-in → auto-detect.
func LookupTool(binary string) ToolDef {
	name := normalizeName(binary)
	if def, ok := profileRegistry[name]; ok {
		return def
	}
	if def, ok := builtinTools[name]; ok {
		return def
	}
	return autoDetectTool(name)
}

// LookupTool on Config checks YAML overrides first, then falls back to
// the package-level lookup (profiles → built-in → auto-detect).
func (c *Config) LookupTool(binary string) ToolDef {
	name := normalizeName(binary)
	if c != nil && c.Tools != nil {
		if def, ok := c.Tools[name]; ok {
			return def
		}
	}
	return LookupTool(binary)
}

// KnownToolNames returns all known tool names from profiles + built-ins.
func KnownToolNames() []string {
	seen := make(map[string]bool)
	var names []string
	for name := range profileRegistry {
		seen[name] = true
		names = append(names, name)
	}
	for name := range builtinTools {
		if !seen[name] {
			names = append(names, name)
		}
	}
	return names
}

// autoDetectTool creates a best-effort ToolDef for an unknown tool by
// probing conventional config paths and environment variables.
func autoDetectTool(name string) ToolDef {
	home, _ := os.UserHomeDir()
	var configDirs []string

	// Convention: ~/.toolname, ~/.config/toolname
	candidates := []string{
		"~/." + name,
		"~/.config/" + name,
	}
	if runtime.GOOS == "windows" {
		candidates = append(candidates, "%APPDATA%/"+name, "%LOCALAPPDATA%/"+name)
	}
	if runtime.GOOS == "darwin" {
		candidates = append(candidates, "~/Library/Application Support/"+name)
	}

	for _, c := range candidates {
		expanded := expandPath(c, home)
		if expanded != "" {
			if _, err := os.Stat(expanded); err == nil {
				configDirs = append(configDirs, c)
			}
		}
	}

	// Auto-detect env keys: TOOLNAME_API_KEY, TOOLNAME_BASE_URL, TOOLNAME_TOKEN
	upper := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	var envKeys []string
	for _, suffix := range []string{"_API_KEY", "_BASE_URL", "_TOKEN"} {
		key := upper + suffix
		if os.Getenv(key) != "" {
			envKeys = append(envKeys, key)
		}
	}

	return ToolDef{
		ConfigDirs: configDirs,
		EnvKeys:    envKeys,
	}
}

func normalizeName(binary string) string {
	name := strings.ToLower(filepath.Base(binary))
	return strings.TrimSuffix(name, ".exe")
}

// existingPaths filters expanded paths to those that exist on disk.
// Duplicate paths (after expansion) are deduplicated; first occurrence wins.
func existingPaths(expanded []string) []string {
	seen := make(map[string]bool, len(expanded))
	result := make([]string, 0, len(expanded))
	for _, p := range expanded {
		if seen[p] {
			continue
		}
		seen[p] = true
		if _, err := os.Stat(p); err == nil {
			result = append(result, p)
		}
	}
	return result
}

func expandPaths(paths []string) []string {
	home, _ := os.UserHomeDir()
	result := make([]string, 0, len(paths))
	for _, p := range paths {
		expanded := expandPath(p, home)
		if expanded != "" {
			result = append(result, expanded)
		}
	}
	return result
}

func expandPath(p, home string) string {
	if p == "~" && home != "" {
		return home
	}
	if strings.HasPrefix(p, "~/") && home != "" {
		return filepath.Join(home, p[2:])
	}
	if strings.HasPrefix(p, "%") {
		if runtime.GOOS != "windows" {
			// %VAR% syntax is Windows-only; skip on other platforms.
			return ""
		}
		end := strings.Index(p[1:], "%")
		if end >= 0 {
			varName := p[1 : end+1]
			val := os.Getenv(varName)
			if val == "" {
				return ""
			}
			rest := p[end+2:]
			rest = strings.TrimPrefix(rest, "/")
			rest = strings.TrimPrefix(rest, "\\")
			return filepath.Join(val, filepath.FromSlash(rest))
		}
	}
	return p
}

// NPMCacheDir returns the platform-appropriate npm cache directory.
func NPMCacheDir() string {
	if d := os.Getenv("npm_config_cache"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "windows" {
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			appdata = filepath.Join(home, "AppData", "Roaming")
		}
		return filepath.Join(appdata, "npm-cache")
	}
	return filepath.Join(home, ".npm")
}

// EnvDirDeps returns toolchain directories discovered from well-known environment
// variables (GOPATH, CARGO_HOME, etc.). Only directories that actually exist on
// disk are returned. These are mounted Force=false — the container backend may
// still filter system directories.
func EnvDirDeps() []string {
	knownDirVars := []string{
		"GOPATH", "GOMODCACHE", "GOCACHE", "GOROOT",
		"CARGO_HOME", "RUSTUP_HOME",
		"VIRTUAL_ENV", "CONDA_PREFIX",
		"NVM_DIR", "VOLTA_HOME", "PNPM_HOME",
	}
	var result []string
	for _, v := range knownDirVars {
		if val := os.Getenv(v); val != "" {
			if info, err := os.Stat(val); err == nil && info.IsDir() {
				result = append(result, val)
			}
		}
	}
	return result
}
