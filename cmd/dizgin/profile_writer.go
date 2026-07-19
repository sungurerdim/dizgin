// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/config"
	"github.com/sungurerdim/dizgin/internal/security"
)

// profileDoc is the on-disk YAML shape written by AppendProfileEntries.
// It mirrors profileFile in internal/config but is declared here because
// the writer lives in cmd/dizgin — keeping the write path independent of
// the reader prevents accidental coupling (e.g. adding a new reader
// field that the writer does not understand).
//
// ConfigDirs uses config.ConfigDirList so legacy bare-string profiles
// (scaffolded by the pre-v2 appendConfigDirsToProfile helper, or
// hand-authored files) decode without error and are upgraded to the
// structured form on the next write.
type profileDoc struct {
	Name       string               `yaml:"name"`
	Version    int                  `yaml:"version"`
	Updated    string               `yaml:"updated,omitempty"`
	Runtime    string               `yaml:"runtime,omitempty"`
	ConfigDirs config.ConfigDirList `yaml:"config_dirs,omitempty"`
}

// userProfilesDir returns the directory user-scoped profile overrides are
// written to. Honours the --profiles CLI flag so automation can redirect
// to a temp dir during tests.
func userProfilesDir() string {
	if profilesDir != "" {
		return profilesDir
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, brand.DotDir, "profiles")
	}
	return "profiles"
}

// AppendProfileEntries merges new config-dirs entries into the user-scope
// profile at ~/.dizgin/profiles/<tool>.yaml. Existing entries with the same
// Path (case insensitive) are upgraded — Mode changes from rw→ro or vice
// versa propagate, but an entry never disappears. The file is scaffolded
// on first use so callers do not have to hand-author it.
//
// Returns the count of NEWLY ADDED entries (upgrades do not count). Zero
// means every supplied entry was already present with the same settings.
func AppendProfileEntries(toolName string, entries []config.ConfigDirEntry) (int, error) {
	if strings.TrimSpace(toolName) == "" {
		return 0, fmt.Errorf("empty tool name")
	}
	if err := security.ValidateToolName(toolName); err != nil {
		return 0, err
	}
	if len(entries) == 0 {
		return 0, nil
	}
	dir := userProfilesDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, fmt.Errorf("mkdir profiles: %w", err)
	}
	target := filepath.Join(dir, strings.ToLower(toolName)+".yaml")

	var doc profileDoc
	if data, err := os.ReadFile(target); err == nil {
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return 0, fmt.Errorf("parse existing profile %s: %w", target, err)
		}
	}
	if doc.Name == "" {
		doc.Name = strings.ToLower(toolName)
	}
	if doc.Version == 0 {
		doc.Version = 1
	}
	doc.Updated = time.Now().UTC().Format("2006-01-02")

	added := 0
	for _, e := range entries {
		if strings.TrimSpace(e.Path) == "" {
			continue
		}
		if e.Mode == "" {
			e.Mode = "rw"
		}
		if e.Source == "" {
			e.Source = "auto"
		}
		if e.Added.IsZero() {
			e.Added = time.Now().UTC()
		}
		idx := -1
		for i, prev := range doc.ConfigDirs {
			if strings.EqualFold(filepath.Clean(prev.Path), filepath.Clean(e.Path)) {
				idx = i
				break
			}
		}
		if idx < 0 {
			doc.ConfigDirs = append(doc.ConfigDirs, e)
			added++
			continue
		}
		// Existing entry — upgrade mode and re-stamp source/added if the
		// new entry is more recent. Never downgrade mode rw→ro unless the
		// caller explicitly re-approved with ro.
		prev := doc.ConfigDirs[idx]
		if !strings.EqualFold(prev.Mode, e.Mode) {
			prev.Mode = e.Mode
		}
		prev.Source = e.Source
		prev.Added = e.Added
		doc.ConfigDirs[idx] = prev
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return 0, fmt.Errorf("marshal profile: %w", err)
	}
	if err := os.WriteFile(target, out, 0o644); err != nil {
		return 0, fmt.Errorf("write profile %s: %w", target, err)
	}
	return added, nil
}

// starterProfileDoc is the minimal valid profile dizgin auto-writes for a
// freshly-detected tool. It must satisfy validateProfile, which requires
// `version` + a `binary` (or `runtime`) — config_dirs/env_keys alone are
// inert. Bare-string config_dirs decode via the loader's legacy path.
type starterProfileDoc struct {
	Name       string   `yaml:"name"`
	Version    int      `yaml:"version"`
	Updated    string   `yaml:"updated,omitempty"`
	Binary     string   `yaml:"binary"`
	ConfigDirs []string `yaml:"config_dirs,omitempty"`
	EnvKeys    []string `yaml:"env_keys,omitempty"`
}

// maybePersistStarterProfile writes ~/.dizgin/profiles/<tool>.yaml for a
// tool that has no registered/built-in profile yet, so the zero-config
// auto-detect result becomes a visible, editable file instead of staying
// implicit. Conservative by design:
//
//   - Skips tools that already have a profile (registry/built-in) or an
//     existing user file — never clobbers user edits (SSOT preserved).
//   - Skips when auto-detect found nothing (no config dir, no env key):
//     running `dizgin -- ls` must not litter the profiles dir with a junk
//     entry for every shell command.
//
// Best-effort: a write failure is reported but never blocks the session.
func maybePersistStarterProfile(toolBin string) {
	name := strings.ToLower(strings.TrimSuffix(filepath.Base(toolBin), ".exe"))
	if name == "" {
		return
	}
	for _, known := range config.KnownToolNames() {
		if strings.EqualFold(known, name) {
			return // already has a profile / built-in
		}
	}
	target := filepath.Join(userProfilesDir(), name+".yaml")
	if _, err := os.Stat(target); err == nil {
		return // user file already exists — never clobber
	}

	def := config.LookupTool(toolBin) // auto-detect result for an unknown tool
	if len(def.ConfigDirs) == 0 && len(def.EnvKeys) == 0 {
		return // nothing detected — not a tool worth a profile
	}

	doc := starterProfileDoc{
		Name:       name,
		Version:    1,
		Updated:    time.Now().UTC().Format("2006-01-02"),
		Binary:     name,
		ConfigDirs: def.ConfigDirs,
		EnvKeys:    def.EnvKeys,
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return
	}
	if err := os.MkdirAll(userProfilesDir(), 0o755); err != nil {
		return
	}
	if err := os.WriteFile(target, out, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, brand.Name+": could not write starter profile %s: %v\n", target, err)
		return
	}
	fmt.Fprintf(os.Stderr, brand.Name+": auto-detected %q — wrote starter profile %s (edit to customize; remove to re-detect)\n",
		name, target)
}

// ReadProfileDoc returns the current on-disk profile for a tool, or an
// empty doc when the file is absent. Used by tests to verify writer
// behaviour without re-parsing YAML manually.
func ReadProfileDoc(toolName string) (profileDoc, error) {
	if err := security.ValidateToolName(toolName); err != nil {
		return profileDoc{}, err
	}
	target := filepath.Join(userProfilesDir(), strings.ToLower(toolName)+".yaml")
	data, err := os.ReadFile(target)
	if err != nil {
		if os.IsNotExist(err) {
			return profileDoc{}, nil
		}
		return profileDoc{}, err
	}
	var doc profileDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return profileDoc{}, err
	}
	return doc, nil
}
