// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/sungurerdim/dizgin/internal/config"
)

// TestMaybePersistStarterProfile_writesForDetectedTool verifies the
// zero-config 4b path: an unknown tool with a detectable credential env
// var gets a valid starter profile written, and a second call is a no-op
// (never clobbers).
func TestMaybePersistStarterProfile_writesForDetectedTool(t *testing.T) {
	dir := t.TempDir()
	profilesDir = dir
	t.Cleanup(func() { profilesDir = "" })
	// Use a name guaranteed NOT to collide with a bundled profile
	// (profiles/example.yaml declares name: mytool, so that name is
	// "known" once the registry loads).
	t.Setenv("ZTESTCLI_API_KEY", "sk-test")

	maybePersistStarterProfile("ztestcli")

	target := filepath.Join(dir, "ztestcli.yaml")
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("starter profile not written: %v", err)
	}
	var doc starterProfileDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("starter profile invalid YAML: %v", err)
	}
	if doc.Binary != "ztestcli" {
		t.Errorf("binary = %q, want ztestcli (required by validateProfile)", doc.Binary)
	}
	if doc.Version != 1 {
		t.Errorf("version = %d, want 1", doc.Version)
	}
	found := false
	for _, k := range doc.EnvKeys {
		if k == "ZTESTCLI_API_KEY" {
			found = true
		}
	}
	if !found {
		t.Errorf("env_keys = %v, want ZTESTCLI_API_KEY", doc.EnvKeys)
	}

	// Second call must not clobber: capture mtime, re-run, assert unchanged.
	before, _ := os.Stat(target)
	maybePersistStarterProfile("ztestcli")
	after, _ := os.Stat(target)
	if !before.ModTime().Equal(after.ModTime()) {
		t.Error("second call rewrote the profile; should skip existing files")
	}

	// Round-trip: the written profile must pass the strict loader
	// (validateProfile requires version + binary). If the loader rejected
	// it, ztestcli would not appear in the registry.
	config.LoadProfiles(dir)
	known := false
	for _, n := range config.KnownToolNames() {
		if n == "ztestcli" {
			known = true
		}
	}
	if !known {
		t.Error("written starter profile was rejected by the strict loader (invalid schema)")
	}
}

// TestMaybePersistStarterProfile_skipsUndetectedCommand ensures a plain
// command with no config dir or env var (e.g. `ls`) does NOT litter the
// profiles directory.
func TestMaybePersistStarterProfile_skipsUndetectedCommand(t *testing.T) {
	dir := t.TempDir()
	profilesDir = dir
	t.Cleanup(func() { profilesDir = "" })

	maybePersistStarterProfile("zzz-nonexistent-cmd")

	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("expected no profile written for undetected command, got %d files", len(entries))
	}
}
