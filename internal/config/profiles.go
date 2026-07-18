// SPDX-License-Identifier: MIT

package config

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/profiles"
)

// profileFile represents a single tool profile YAML file. ConfigDirs uses
// the ConfigDirList wrapper so it accepts both the legacy bare-string
// form and the structured form (path + mode + source) inside the same
// YAML sequence.
//
// The Network field captures profile-suggested allowlist hosts. It is
// not yet consumed by the loader but is preserved here so the bundled
// profiles parse cleanly under yaml strict-mode (KnownFields(true))
// rather than blowing up on a documented but currently-inert key.
// Wiring `Network.Hosts` into the runtime allowlist policy is tracked
// in docs/ROADMAP.md under "WFP (Windows Filtering Platform) callout
// driver allowlist" — the data survives in memory until that ships.
type profileFile struct {
	Name            string            `yaml:"name"`
	Version         int               `yaml:"version"`
	Updated         string            `yaml:"updated"`
	Description     string            `yaml:"description"`
	Binary          string            `yaml:"binary"`
	Runtime         string            `yaml:"runtime"`
	ConfigDirs      ConfigDirList     `yaml:"config_dirs"`
	ToolDeps        []string          `yaml:"tool_deps"`
	LibDeps         []string          `yaml:"lib_deps"`
	MCPDirs         []string          `yaml:"mcp_dirs"`
	RuntimeDirs     []string          `yaml:"runtime_dirs"`
	ExcludeDefaults []string          `yaml:"exclude_defaults"`
	EnvKeys         []string          `yaml:"env_keys"`
	Passthrough     []string          `yaml:"passthrough"`
	DefaultArgs     []string          `yaml:"default_args"`
	Env             map[string]string `yaml:"env"`
	Network         profileNetwork    `yaml:"network"`
	Compatibility   Compatibility     `yaml:"compatibility"`
}

// profileNetwork is the parking field for profile-suggested allowlist
// data. Shape mirrors what the bundled profiles already write today.
type profileNetwork struct {
	Hosts []string `yaml:"hosts"`
}

// LoadProfiles loads tool profiles in priority order (later sources override earlier):
//
//  1. Embedded profiles (compiled into the binary — always available)
//  2. ~/.dizgin/profiles/ (user-local customisations)
//  3. extraDir (--profiles flag — highest priority, for advanced users)
func LoadProfiles(extraDir string) {
	dest := make(map[string]ToolDef)

	loadProfileFS(profiles.FS, dest)
	if home, _ := os.UserHomeDir(); home != "" {
		loadProfileDir(filepath.Join(home, brand.DotDir, "profiles"), dest)
	}
	if extraDir != "" {
		loadProfileDir(extraDir, dest)
	}

	SetProfiles(dest)
}

// bundledExampleProfile is the documentation/template YAML shipped in
// profiles/ for users to copy — not a real tool, so it must not inflate
// the user-facing tool count (`dizgin doctor`, README) or appear as an
// auto-detected/known tool name.
const bundledExampleProfile = "example.yaml"

// loadProfileFS reads all *.yaml files from an fs.FS and merges into dest.
func loadProfileFS(fsys fs.FS, dest map[string]ToolDef) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") || e.Name() == bundledExampleProfile {
			continue
		}
		data, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			fmt.Fprintf(os.Stderr, brand.Name+": profile: skip %s: %v\n", e.Name(), err)
			continue
		}
		parseProfile(e.Name(), data, dest)
	}
}

// loadProfileDir reads all *.yaml files in an on-disk directory and merges into dest.
// Missing directories are silently ignored.
func loadProfileDir(dir string, dest map[string]ToolDef) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return // dir doesn't exist — OK
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			fmt.Fprintf(os.Stderr, brand.Name+": profile: skip %s: %v\n", e.Name(), err)
			continue
		}
		parseProfile(e.Name(), data, dest)
	}
}

// supportedProfileVersion is the only profile schema version this
// loader understands. A future schema bump emits a new value here AND a
// migration path in parseProfile.
const supportedProfileVersion = 1

// parseProfile unmarshals one YAML file and stores the result in dest.
// When a profile for the same tool is already present (e.g. embedded
// default loaded first, then user override), the second profile's
// ConfigDirMounts are APPENDED rather than replacing — this is the
// auto-grow contract that lets user-scope entries accumulate without
// wiping the bundled base list.
//
// Schema validation (Phase 1 plan, item F5):
//
//   - yaml.v3 strict-mode decoder (KnownFields(true)) — unknown keys
//     in the YAML cause a hard error. Catches typos like `mcp_dir:`
//     instead of `mcp_dirs:` that the previous lenient Unmarshal
//     silently ignored.
//   - validateProfile post-pass — version range, derived-name rule,
//     empty-binary check. Loud failure with the source filename in
//     the message so users know which file to fix.
//
// Profiles that fail validation are skipped (with stderr log) rather
// than aborting the whole loader pass — a single bad user profile
// must not knock out the bundled defaults.
func parseProfile(filename string, data []byte, dest map[string]ToolDef) {
	pf, ok := decodeAndValidateProfile(filename, data)
	if !ok {
		return
	}

	name := pf.Name
	if name == "" {
		name = strings.TrimSuffix(filename, ".yaml")
	}
	key := strings.ToLower(name)

	mounts := []ConfigDirEntry(pf.ConfigDirs)
	legacy := pf.ConfigDirs.Paths()

	if existing, ok := dest[key]; ok {
		mergeProfileInto(&existing, pf, mounts)
		dest[key] = existing
		return
	}

	dest[key] = ToolDef{
		ConfigDirs:      legacy,
		ConfigDirMounts: mounts,
		ToolDeps:        pf.ToolDeps,
		LibDeps:         pf.LibDeps,
		MCPDirs:         pf.MCPDirs,
		RuntimeDirs:     pf.RuntimeDirs,
		ExcludeDefaults: pf.ExcludeDefaults,
		EnvKeys:         pf.EnvKeys,
		Passthrough:     pf.Passthrough,
		DefaultArgs:     pf.DefaultArgs,
		Env:             pf.Env,
		Runtime:         pf.Runtime,
		Compatibility:   pf.Compatibility,
	}
}

// decodeAndValidateProfile unmarshals YAML from data using strict-mode decode,
// then runs semantic validation. Returns (pf, true) on success or (zero, false)
// with a diagnostic already printed to stderr.
func decodeAndValidateProfile(filename string, data []byte) (profileFile, bool) {
	var pf profileFile
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&pf); err != nil {
		fmt.Fprintf(os.Stderr, brand.Name+": profile: parse %s: %v\n", filename, err)
		return profileFile{}, false
	}
	if err := validateProfile(filename, &pf); err != nil {
		fmt.Fprintf(os.Stderr, brand.Name+": profile: %v\n", err)
		return profileFile{}, false
	}
	return pf, true
}

// mergeProfileInto applies the fields of pf (an override profile) onto existing.
// Merge rules:
//   - ConfigDirMounts: new entries appended; same path (case-insensitive) replaced.
//   - Slice scalar fields: later profile wins when non-empty.
//   - Env map: later profile's keys win for duplicates.
//   - Compatibility: later profile's non-nil pointer fields win.
func mergeProfileInto(existing *ToolDef, pf profileFile, mounts []ConfigDirEntry) {
	// Merge mode: append new entries to existing (later source wins for
	// duplicates — user profile overrides embedded default when path
	// matches case-insensitively).
	merged := append([]ConfigDirEntry{}, existing.ConfigDirMounts...)
	for _, e := range mounts {
		idx := -1
		for i, prev := range merged {
			if strings.EqualFold(prev.Path, e.Path) {
				idx = i
				break
			}
		}
		if idx >= 0 {
			merged[idx] = e
		} else {
			merged = append(merged, e)
		}
	}
	existing.ConfigDirMounts = merged
	// Keep the legacy []string in sync for any code path that still reads it.
	paths := make([]string, 0, len(merged))
	for _, e := range merged {
		paths = append(paths, e.Path)
	}
	existing.ConfigDirs = paths

	// Scalar fields: later profile wins when non-zero.
	if pf.Runtime != "" {
		existing.Runtime = pf.Runtime
	}
	if len(pf.ToolDeps) > 0 {
		existing.ToolDeps = pf.ToolDeps
	}
	if len(pf.LibDeps) > 0 {
		existing.LibDeps = pf.LibDeps
	}
	if len(pf.MCPDirs) > 0 {
		existing.MCPDirs = pf.MCPDirs
	}
	if len(pf.RuntimeDirs) > 0 {
		existing.RuntimeDirs = pf.RuntimeDirs
	}
	if len(pf.ExcludeDefaults) > 0 {
		existing.ExcludeDefaults = pf.ExcludeDefaults
	}
	if len(pf.EnvKeys) > 0 {
		existing.EnvKeys = pf.EnvKeys
	}
	if len(pf.Passthrough) > 0 {
		existing.Passthrough = pf.Passthrough
	}
	if len(pf.DefaultArgs) > 0 {
		existing.DefaultArgs = pf.DefaultArgs
	}
	if len(pf.Env) > 0 {
		if existing.Env == nil {
			existing.Env = map[string]string{}
		}
		for k, v := range pf.Env {
			existing.Env[k] = v
		}
	}
	// Compatibility merge: later profile's explicit fields win,
	// unset fields preserve the existing value. Pointer nil-check
	// is what gives us "unset" semantics — `false` from the
	// override still has to overwrite an earlier `true`.
	if pf.Compatibility.TempOverride != nil {
		existing.Compatibility.TempOverride = pf.Compatibility.TempOverride
	}
	if pf.Compatibility.HandleListAllowlist != nil {
		existing.Compatibility.HandleListAllowlist = pf.Compatibility.HandleListAllowlist
	}
	if pf.Compatibility.AllowDynamicCode != nil {
		existing.Compatibility.AllowDynamicCode = pf.Compatibility.AllowDynamicCode
	}
	if pf.Compatibility.AllowLowLabelImages != nil {
		existing.Compatibility.AllowLowLabelImages = pf.Compatibility.AllowLowLabelImages
	}
}

// validateProfile enforces the semantic invariants the type system
// can't express in a YAML struct: supported version, non-zero
// effective name, and the runtime/binary contract (a profile that
// declares neither tells dizgin nothing actionable). Errors carry the
// source filename so users can locate the offending file at a glance.
func validateProfile(filename string, pf *profileFile) error {
	if pf.Version != 0 && pf.Version != supportedProfileVersion {
		return fmt.Errorf("%s: unsupported profile version %d (want %d)",
			filename, pf.Version, supportedProfileVersion)
	}
	effectiveName := pf.Name
	if effectiveName == "" {
		effectiveName = strings.TrimSuffix(filename, ".yaml")
	}
	if effectiveName == "" {
		return fmt.Errorf("%s: profile has empty name and no filename to derive from", filename)
	}
	// A profile with no executable target and no runtime delegation is
	// inert — dizgin would resolve it to "nothing to mount, nothing to
	// run". Catching this at load time saves a confusing "tool not
	// found" error at the session boundary.
	if strings.TrimSpace(pf.Binary) == "" && strings.TrimSpace(pf.Runtime) == "" {
		return fmt.Errorf("%s (%s): must declare either binary or runtime",
			filename, effectiveName)
	}
	return nil
}
