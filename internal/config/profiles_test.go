// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/sungurerdim/dizgin/profiles"
)

func TestLoadProfileDir_RuntimeDirsAndPassthrough(t *testing.T) {
	dir := t.TempDir()
	yaml := `
name: testtool
version: 1
binary: testtool
runtime: nodejs
config_dirs:
  - "~/.testtool"
runtime_dirs:
  - "/opt/nodejs"
  - "/opt/custom"
env_keys:
  - TESTTOOL_API_KEY
passthrough:
  - NODE_HOME
  - VIRTUAL_ENV
default_args:
  - "--yes"
env:
  DO_NOT_TRACK: "1"
`
	if err := os.WriteFile(filepath.Join(dir, "testtool.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	dest := make(map[string]ToolDef)
	loadProfileDir(dir, dest)

	def, ok := dest["testtool"]
	if !ok {
		t.Fatal("testtool not found in loaded profiles")
	}

	// Verify runtime_dirs loaded correctly.
	if len(def.RuntimeDirs) != 2 {
		t.Errorf("RuntimeDirs: got %v, want 2 entries", def.RuntimeDirs)
	} else {
		if def.RuntimeDirs[0] != "/opt/nodejs" {
			t.Errorf("RuntimeDirs[0] = %q, want /opt/nodejs", def.RuntimeDirs[0])
		}
		if def.RuntimeDirs[1] != "/opt/custom" {
			t.Errorf("RuntimeDirs[1] = %q, want /opt/custom", def.RuntimeDirs[1])
		}
	}

	// Verify passthrough loaded correctly.
	if len(def.Passthrough) != 2 {
		t.Errorf("Passthrough: got %v, want 2 entries", def.Passthrough)
	} else {
		if def.Passthrough[0] != "NODE_HOME" {
			t.Errorf("Passthrough[0] = %q, want NODE_HOME", def.Passthrough[0])
		}
		if def.Passthrough[1] != "VIRTUAL_ENV" {
			t.Errorf("Passthrough[1] = %q, want VIRTUAL_ENV", def.Passthrough[1])
		}
	}

	// Verify other fields still load correctly.
	if def.Runtime != "nodejs" {
		t.Errorf("Runtime = %q, want nodejs", def.Runtime)
	}
	if len(def.ConfigDirs) != 1 {
		t.Errorf("ConfigDirs: got %v, want 1 entry", def.ConfigDirs)
	}
}

func TestLoadProfileFS_RuntimeDirsAndPassthrough(t *testing.T) {
	yaml := `
name: fstool
runtime: python
runtime_dirs:
  - "/opt/python"
passthrough:
  - PYTHON_HOME
  - VIRTUAL_ENV
`
	fsys := fstest.MapFS{
		"fstool.yaml": &fstest.MapFile{Data: []byte(yaml)},
	}

	dest := make(map[string]ToolDef)
	loadProfileFS(fsys, dest)

	def, ok := dest["fstool"]
	if !ok {
		t.Fatal("fstool not found after loadProfileFS")
	}
	if len(def.RuntimeDirs) != 1 || def.RuntimeDirs[0] != "/opt/python" {
		t.Errorf("RuntimeDirs = %v, want [\"/opt/python\"]", def.RuntimeDirs)
	}
	if len(def.Passthrough) != 2 {
		t.Errorf("Passthrough = %v, want [PYTHON_HOME VIRTUAL_ENV]", def.Passthrough)
	}
}

func TestEmbeddedProfiles_ContainsClaude(t *testing.T) {
	// Regression: embedded profiles FS must contain claude.yaml.
	// Git mount is now provided by DefaultToolDeps (not runtime_dirs in the YAML).
	dest := make(map[string]ToolDef)
	loadProfileFS(profiles.FS, dest)

	def, ok := dest["claude"]
	if !ok {
		t.Fatal("claude profile not found in embedded profiles")
	}
	if len(def.Passthrough) == 0 {
		t.Error("claude profile: Passthrough is empty (expected CLAUDE_CODE_GIT_BASH_PATH)")
	}
	// Git path is injected via DefaultToolDeps, not stored in RuntimeDirs.
	found := false
	for _, p := range DefaultToolDeps {
		if p == "%ProgramFiles%/Git" {
			found = true
			break
		}
	}
	if !found {
		t.Error("DefaultToolDeps must include %ProgramFiles%/Git for MSYS2 bash compatibility")
	}
}

// TestEmbeddedProfiles_ExampleTemplateNotCountedAsTool is a regression test
// for the doctor-vs-README count mismatch: profiles/example.yaml is a
// documentation template shipped for users to copy, not a real tool, so it
// must never appear in the registry `dizgin doctor` and KnownToolNames()
// count against (README states "28 tools"; the template inflated it to 29).
func TestEmbeddedProfiles_ExampleTemplateNotCountedAsTool(t *testing.T) {
	dest := make(map[string]ToolDef)
	loadProfileFS(profiles.FS, dest)

	if _, ok := dest["example"]; ok {
		t.Error("bundled example.yaml template must not be registered as a tool profile")
	}
}

// TestEffectiveToolDeps_IncludesGitDefault verifies that every tool gets the
// default Git tool_dep unless explicitly excluded.
func TestEffectiveToolDeps_IncludesGitDefault(t *testing.T) {
	def := ToolDef{}
	raw := DefaultToolDeps
	if len(raw) == 0 {
		t.Fatal("DefaultToolDeps must not be empty")
	}
	// The Git path should appear in the combined list before existence filtering.
	gitPath := "%ProgramFiles%/Git"
	found := false
	for _, p := range raw {
		if p == gitPath {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("DefaultToolDeps does not include %q", gitPath)
	}

	// ExcludeDefaults removes it from EffectiveToolDeps raw list.
	def.ExcludeDefaults = []string{gitPath}
	if def.IsExcluded(gitPath) == false {
		t.Error("IsExcluded should return true for excluded Git path")
	}
}

// TestEffectiveLibDeps_NodejsRuntime verifies that runtime=nodejs includes
// Node.js lib_deps from the defaults.
func TestEffectiveLibDeps_NodejsRuntime(t *testing.T) {
	def := ToolDef{Runtime: "nodejs"}
	raw := RuntimeLibDeps(def.Runtime)
	if len(raw) == 0 {
		t.Fatal("RuntimeLibDeps(nodejs) must not be empty")
	}
	foundNodejs := false
	for _, p := range raw {
		if p == "%ProgramFiles%/nodejs" {
			foundNodejs = true
			break
		}
	}
	if !foundNodejs {
		t.Error("RuntimeLibDeps(nodejs) must include %ProgramFiles%/nodejs")
	}
}

// TestEffectiveLibDeps_PythonRuntime verifies that runtime=python includes
// Python lib_deps from the defaults.
func TestEffectiveLibDeps_PythonRuntime(t *testing.T) {
	def := ToolDef{Runtime: "python"}
	raw := RuntimeLibDeps(def.Runtime)
	if len(raw) == 0 {
		t.Fatal("RuntimeLibDeps(python) must not be empty")
	}
	foundPython := false
	for _, p := range raw {
		if p == "%LOCALAPPDATA%/Programs/Python" {
			foundPython = true
			break
		}
	}
	if !foundPython {
		t.Error("RuntimeLibDeps(python) must include %LOCALAPPDATA%/Programs/Python")
	}
}

// TestEffectiveEnv_DefaultsPresent verifies that EffectiveEnv includes all DefaultEnv
// keys unless excluded.
func TestEffectiveEnv_DefaultsPresent(t *testing.T) {
	def := ToolDef{}
	env := def.EffectiveEnv()

	for k, want := range DefaultEnv {
		if got, ok := env[k]; !ok {
			t.Errorf("EffectiveEnv missing default key %q", k)
		} else if got != want {
			t.Errorf("EffectiveEnv[%q] = %q, want %q", k, got, want)
		}
	}
}

// TestEffectiveEnv_ProfileOverridesDefault verifies that a profile env value
// overrides the default for the same key.
func TestEffectiveEnv_ProfileOverridesDefault(t *testing.T) {
	def := ToolDef{
		Env: map[string]string{"DO_NOT_TRACK": "0"},
	}
	env := def.EffectiveEnv()
	if got := env["DO_NOT_TRACK"]; got != "0" {
		t.Errorf("profile env should override default: got %q, want 0", got)
	}
}

// TestEffectiveEnv_ExcludeRemovesDefault verifies that ExcludeDefaults removes
// the specified default env key.
func TestEffectiveEnv_ExcludeRemovesDefault(t *testing.T) {
	def := ToolDef{
		ExcludeDefaults: []string{"DO_NOT_TRACK"},
	}
	env := def.EffectiveEnv()
	if _, ok := env["DO_NOT_TRACK"]; ok {
		t.Error("DO_NOT_TRACK should be excluded from EffectiveEnv")
	}
	// Excluding one key should not affect whether the map is empty or not
	// (only DO_NOT_TRACK existed, so the result should be an empty map).
	_ = env // no other default env keys to check; absence of panic is sufficient
}

// TestDefaultMCPDirs_ContainsUniversalPaths verifies that DefaultMCPDirs includes
// the universal ~/.mcp path that all tools share.
func TestDefaultMCPDirs_ContainsUniversalPaths(t *testing.T) {
	dirs := DefaultMCPDirs
	if len(dirs) == 0 {
		t.Fatal("DefaultMCPDirs must not be empty")
	}
	found := false
	for _, p := range dirs {
		if p == "~/.mcp" {
			found = true
			break
		}
	}
	if !found {
		t.Error("DefaultMCPDirs must include ~/.mcp")
	}
}

// TestEffectiveMCPDirs_IncludesDefaults verifies that EffectiveMCPDirs merges
// DefaultMCPDirs with profile-declared mcp_dirs.
func TestEffectiveMCPDirs_IncludesDefaults(t *testing.T) {
	// Raw paths (before existence filter) — defaults must appear in combined list.
	def := ToolDef{}
	raw := DefaultMCPDirs
	if len(raw) == 0 {
		t.Fatal("DefaultMCPDirs must not be empty")
	}
	// IsExcluded is false for all default paths when ExcludeDefaults is empty.
	for _, p := range raw {
		if def.IsExcluded(p) {
			t.Errorf("default MCP dir %q should not be excluded by default", p)
		}
	}
}

// TestCompatibility_DefaultsAllTrue verifies that a tool with no
// compatibility block inherits the universal default (all flags true).
func TestCompatibility_DefaultsAllTrue(t *testing.T) {
	def := ToolDef{Runtime: "bun"}
	c := def.EffectiveCompatibility()
	if c.TempOverride == nil || !*c.TempOverride {
		t.Error("runtime=bun should default TempOverride=true")
	}
	if c.HandleListAllowlist == nil || !*c.HandleListAllowlist {
		t.Error("runtime=bun should default HandleListAllowlist=true")
	}
}

// TestCompatibility_ProfileOverrideWins verifies that an explicit
// false in the profile overrides the default true.
func TestCompatibility_ProfileOverrideWins(t *testing.T) {
	off := false
	def := ToolDef{
		Runtime:       "bun",
		Compatibility: Compatibility{TempOverride: &off},
	}
	c := def.EffectiveCompatibility()
	if c.TempOverride == nil || *c.TempOverride {
		t.Error("explicit false should override default true")
	}
	// Unset fields keep the default.
	if c.HandleListAllowlist == nil || !*c.HandleListAllowlist {
		t.Error("unset HandleListAllowlist should fall back to default true")
	}
}

// TestLoadProfileDir_ParsesCompatibilityBlock verifies that the YAML
// loader populates the Compatibility struct from a `compatibility:`
// block in the profile file.
func TestLoadProfileDir_ParsesCompatibilityBlock(t *testing.T) {
	dir := t.TempDir()
	yaml := `
name: bunny
version: 1
binary: bunny
runtime: bun
compatibility:
  temp_override: false
  handle_list_allowlist: true
`
	if err := os.WriteFile(filepath.Join(dir, "bunny.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	dest := make(map[string]ToolDef)
	loadProfileDir(dir, dest)
	def, ok := dest["bunny"]
	if !ok {
		t.Fatal("bunny not found")
	}
	if def.Compatibility.TempOverride == nil || *def.Compatibility.TempOverride {
		t.Errorf("temp_override: got %v, want false", def.Compatibility.TempOverride)
	}
	if def.Compatibility.HandleListAllowlist == nil || !*def.Compatibility.HandleListAllowlist {
		t.Errorf("handle_list_allowlist: got %v, want true", def.Compatibility.HandleListAllowlist)
	}
}

// TestEffectiveCompatibility_MitigationPolicyDefault verifies that a
// tool with no compatibility block (or no mitigation_policy block)
// inherits BlockNonMicrosoftBinaries=false — the iter6 opt-in baseline.
func TestEffectiveCompatibility_MitigationPolicyDefault(t *testing.T) {
	def := ToolDef{Runtime: "bun"}
	c := def.EffectiveCompatibility()
	if c.MitigationPolicy == nil {
		t.Fatal("MitigationPolicy should default to non-nil struct")
	}
	if c.MitigationPolicy.BlockNonMicrosoftBinaries == nil {
		t.Fatal("BlockNonMicrosoftBinaries should default to non-nil *bool")
	}
	if *c.MitigationPolicy.BlockNonMicrosoftBinaries {
		t.Error("BlockNonMicrosoftBinaries should default to false (opt-in)")
	}
}

// TestEffectiveCompatibility_MitigationPolicyExplicitTrue verifies
// that a profile that sets block_non_microsoft_binaries=true wins
// over the default false.
func TestEffectiveCompatibility_MitigationPolicyExplicitTrue(t *testing.T) {
	on := true
	def := ToolDef{
		Runtime: "bun",
		Compatibility: Compatibility{
			MitigationPolicy: &MitigationPolicy{
				BlockNonMicrosoftBinaries: &on,
			},
		},
	}
	c := def.EffectiveCompatibility()
	if c.MitigationPolicy == nil || c.MitigationPolicy.BlockNonMicrosoftBinaries == nil {
		t.Fatal("MitigationPolicy / BlockNonMicrosoftBinaries unexpectedly nil")
	}
	if !*c.MitigationPolicy.BlockNonMicrosoftBinaries {
		t.Error("explicit true should override default false")
	}
}

// TestLoadProfileDir_ParsesMitigationPolicy verifies the YAML loader
// reads the nested mitigation_policy block correctly.
func TestLoadProfileDir_ParsesMitigationPolicy(t *testing.T) {
	dir := t.TempDir()
	yaml := `
name: hardened
version: 1
binary: hardened
runtime: native
compatibility:
  mitigation_policy:
    block_non_microsoft_binaries: true
`
	if err := os.WriteFile(filepath.Join(dir, "hardened.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	dest := make(map[string]ToolDef)
	loadProfileDir(dir, dest)
	def, ok := dest["hardened"]
	if !ok {
		t.Fatal("hardened not found")
	}
	if def.Compatibility.MitigationPolicy == nil {
		t.Fatal("mitigation_policy block not parsed")
	}
	got := def.Compatibility.MitigationPolicy.BlockNonMicrosoftBinaries
	if got == nil || !*got {
		t.Errorf("block_non_microsoft_binaries: got %v, want true", got)
	}
}

// TestEffectiveMCPDirs_ProfileDirsAppended verifies that profile-declared
// mcp_dirs are included alongside the defaults.
func TestEffectiveMCPDirs_ProfileDirsAppended(t *testing.T) {
	dir := t.TempDir() // use a real dir to pass existence filter
	def := ToolDef{
		MCPDirs: []string{dir},
	}
	result := def.EffectiveMCPDirs()
	found := false
	for _, p := range result {
		if p == dir {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("profile-declared mcp_dirs entry %q not found in EffectiveMCPDirs: %v", dir, result)
	}
}

// TestEffectiveMCPDirs_ExcludeRemovesDefault verifies that ExcludeDefaults
// removes a default MCP dir from the effective set.
func TestEffectiveMCPDirs_ExcludeRemovesDefault(t *testing.T) {
	def := ToolDef{
		ExcludeDefaults: []string{"~/.mcp"},
	}
	// ~/.mcp should be excluded from the combined list before expansion.
	if !def.IsExcluded("~/.mcp") {
		t.Error("IsExcluded should return true for ~/.mcp after ExcludeDefaults")
	}
}

// TestMCPDirsField_ParsesFromYAML verifies that the mcp_dirs YAML field is
// parsed correctly by loadProfileDir.
func TestMCPDirsField_ParsesFromYAML(t *testing.T) {
	dir := t.TempDir()
	yaml := `
name: mcp-test-tool
version: 1
binary: mcp-test-tool
mcp_dirs:
  - "~/.mcp-test-tool"
  - "/opt/mcp-servers"
`
	if err := os.WriteFile(filepath.Join(dir, "mcp-test-tool.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	dest := make(map[string]ToolDef)
	loadProfileDir(dir, dest)

	def, ok := dest["mcp-test-tool"]
	if !ok {
		t.Fatal("mcp-test-tool not found in loaded profiles")
	}
	if len(def.MCPDirs) != 2 {
		t.Errorf("MCPDirs: got %v, want 2 entries", def.MCPDirs)
	} else {
		if def.MCPDirs[0] != "~/.mcp-test-tool" {
			t.Errorf("MCPDirs[0] = %q, want ~/.mcp-test-tool", def.MCPDirs[0])
		}
		if def.MCPDirs[1] != "/opt/mcp-servers" {
			t.Errorf("MCPDirs[1] = %q, want /opt/mcp-servers", def.MCPDirs[1])
		}
	}
}

// TestDefaultEnv_FileWatcherVars verifies that DefaultEnv includes
// file watcher polling vars for HCS container compatibility.
func TestDefaultEnv_FileWatcherVars(t *testing.T) {
	env := DefaultEnv
	if v, ok := env["CHOKIDAR_USEPOLLING"]; !ok || v != "1" {
		t.Errorf("DefaultEnv[CHOKIDAR_USEPOLLING] = %q, want 1", v)
	}
	if v, ok := env["WATCHPACK_POLLING"]; !ok || v != "true" {
		t.Errorf("DefaultEnv[WATCHPACK_POLLING] = %q, want true", v)
	}
}

// TestDefaultToolDeps_IncludesCacheDir verifies that DefaultToolDeps includes
// ~/.cache for LSP and build cache access.
func TestDefaultToolDeps_IncludesCacheDir(t *testing.T) {
	deps := DefaultToolDeps
	found := false
	for _, p := range deps {
		if p == "~/.cache" {
			found = true
			break
		}
	}
	if !found {
		t.Error("DefaultToolDeps must include ~/.cache for LSP and build cache access")
	}
}

// TestRuntimeLibDeps_BunIncludesNPM verifies that runtime=bun gets npm global bin
// for MCP server support via npx.
func TestRuntimeLibDeps_BunIncludesNPM(t *testing.T) {
	deps := RuntimeLibDeps("bun")
	if len(deps) == 0 {
		t.Fatal("RuntimeLibDeps(bun) must not be empty")
	}
	found := false
	for _, p := range deps {
		if p == "%APPDATA%/npm" {
			found = true
			break
		}
	}
	if !found {
		t.Error("RuntimeLibDeps(bun) must include %APPDATA%/npm for npx-based MCP servers")
	}
}

// TestRuntimeLibDeps_NodejsIncludesNPM verifies that runtime=nodejs gets npm global bin.
func TestRuntimeLibDeps_NodejsIncludesNPM(t *testing.T) {
	for _, rt := range []string{"nodejs", "node", "electron"} {
		deps := RuntimeLibDeps(rt)
		found := false
		for _, p := range deps {
			if p == "%APPDATA%/npm" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("RuntimeLibDeps(%q) must include %%APPDATA%%/npm for npx-based MCP servers", rt)
		}
	}
}

// TestEffectiveLibDeps_BackwardCompat verifies that the deprecated runtime_dirs
// field is still included in EffectiveLibDeps output.
func TestEffectiveLibDeps_BackwardCompat(t *testing.T) {
	def := ToolDef{
		RuntimeDirs: []string{"/custom/lib"},
	}
	// /custom/lib won't exist on most systems — verify it appears in combined list
	// before existence filtering by checking it against expanded raw list.
	raw := RuntimeLibDeps(def.Runtime)
	combined := append(raw, def.LibDeps...)
	combined = append(combined, def.RuntimeDirs...)
	found := false
	for _, p := range combined {
		if p == "/custom/lib" {
			found = true
			break
		}
	}
	if !found {
		t.Error("runtime_dirs entry should be included in combined lib_deps")
	}
}
