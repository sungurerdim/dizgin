// SPDX-License-Identifier: MIT

package config

// ToolDef describes the config, credentials, and runtime needs of an AI tool.
// Loaded from YAML profiles (profiles/*.yaml), built-in registry, or auto-detected.
//
// ConfigDirs is the legacy bare-path list kept for mapstructure (dizgin.yaml
// via viper) and for compatibility with older callers. New code should
// prefer ConfigDirMounts, which carries per-entry Mode ("rw"|"ro") and
// Source ("profile"|"auto"|"manual") metadata. When both are populated,
// ConfigDirMounts is authoritative and ConfigDirs is only used as a
// fallback.
type ToolDef struct {
	ConfigDirs      []string          `mapstructure:"config_dirs"       yaml:"config_dirs"`
	ConfigDirMounts []ConfigDirEntry  `mapstructure:"-"                 yaml:"-"`
	ToolDeps        []string          `mapstructure:"tool_deps"         yaml:"tool_deps"`
	LibDeps         []string          `mapstructure:"lib_deps"          yaml:"lib_deps"`
	MCPDirs         []string          `mapstructure:"mcp_dirs"          yaml:"mcp_dirs"`         // MCP server config/binary directories (R/W)
	ToolchainDeps   []string          `mapstructure:"toolchain_deps"    yaml:"toolchain_deps"`   // build toolchain home dirs (GOPATH, Cargo, Rustup, etc.)
	RuntimeDirs     []string          `mapstructure:"runtime_dirs"      yaml:"runtime_dirs"`     // deprecated alias for LibDeps
	ExcludeDefaults []string          `mapstructure:"exclude_defaults"  yaml:"exclude_defaults"` // opt-out specific default paths/env-keys
	EnvKeys         []string          `mapstructure:"env_keys"          yaml:"env_keys"`
	Passthrough     []string          `mapstructure:"passthrough"       yaml:"passthrough"`
	DefaultArgs     []string          `mapstructure:"default_args"      yaml:"default_args"`
	Env             map[string]string `mapstructure:"env"               yaml:"env"`
	Runtime         string            `mapstructure:"runtime"           yaml:"runtime"`
	Compatibility   Compatibility     `mapstructure:"compatibility"     yaml:"compatibility"`
}

// Compatibility expresses per-tool toggles for dizgin's defence-in-depth
// hardening. Each field is a *bool so unset → fall back to the
// runtime-derived default (see EffectiveCompatibility). Tools with
// runtime=bun automatically opt into temp_override + handle_list_allowlist
// because their self-extracting executable layout depends on both;
// other runtimes default to "use dizgin's compiled defaults" and require
// an explicit override to deviate.
//
// allow_dynamic_code and allow_low_label_images are forward-looking:
// dizgin does not currently emit either mitigation policy (no
// PROHIBIT_DYNAMIC_CODE / IMAGE_LOAD_NO_LOW_LABEL today). Reserving
// the YAML field now means future hardening passes can ship without
// breaking existing profiles' strict-mode parse.
//
// mitigation_policy is a nested struct (rather than a flat field) so
// the next process-mitigation toggle can ship without another YAML
// shape change. iter6 only wires block_non_microsoft_binaries; the
// rest of the Policies bitfield (DEP / ASLR / ImageLoadHardening) is
// not user-tunable today because flipping those off has no realistic
// use case — they always stay ON.
type Compatibility struct {
	TempOverride        *bool             `mapstructure:"temp_override"          yaml:"temp_override"`
	HandleListAllowlist *bool             `mapstructure:"handle_list_allowlist"  yaml:"handle_list_allowlist"`
	AllowDynamicCode    *bool             `mapstructure:"allow_dynamic_code"     yaml:"allow_dynamic_code"`
	AllowLowLabelImages *bool             `mapstructure:"allow_low_label_images" yaml:"allow_low_label_images"`
	MitigationPolicy    *MitigationPolicy `mapstructure:"mitigation_policy"      yaml:"mitigation_policy"`
}

// MitigationPolicy exposes the process-mitigation toggles a profile
// may override on the restricted backend. iter6 ships one field;
// future toggles slot in here without a second nested struct.
//
// Each field is a *bool so unset → "use the backend's compiled
// default" (currently false for BlockNonMicrosoftBinaries — opt-in
// only because it breaks most third-party tools by design).
type MitigationPolicy struct {
	BlockNonMicrosoftBinaries *bool `mapstructure:"block_non_microsoft_binaries" yaml:"block_non_microsoft_binaries"`
}

// EffectiveCompatibility returns the materialised compatibility flags
// for this tool: explicit field wins if set, otherwise the
// runtime-derived default fills in. runtime=bun tools default
// TempOverride and HandleListAllowlist to true (their self-extracting
// runtime layout requires both); all other runtimes default each
// flag to true as well — the iter5 layer toggles are documented as
// "on unless something explicitly turns them off", and the env-var
// emergency switches DIZGIN_NO_TEMP_OVERRIDE / DIZGIN_NO_HANDLE_LIST
// stay as the run-time escape hatch even when the YAML says ON.
func (t ToolDef) EffectiveCompatibility() Compatibility {
	c := t.Compatibility
	def := defaultCompatibilityForRuntime(t.Runtime)
	if c.TempOverride == nil {
		c.TempOverride = def.TempOverride
	}
	if c.HandleListAllowlist == nil {
		c.HandleListAllowlist = def.HandleListAllowlist
	}
	if c.AllowDynamicCode == nil {
		c.AllowDynamicCode = def.AllowDynamicCode
	}
	if c.AllowLowLabelImages == nil {
		c.AllowLowLabelImages = def.AllowLowLabelImages
	}
	if c.MitigationPolicy == nil {
		c.MitigationPolicy = def.MitigationPolicy
	} else if c.MitigationPolicy.BlockNonMicrosoftBinaries == nil && def.MitigationPolicy != nil {
		// Per-field fallthrough — profile may set the nested struct but
		// omit a specific toggle, in which case we still want the
		// runtime-derived default for that toggle instead of a nil panic
		// downstream.
		c.MitigationPolicy.BlockNonMicrosoftBinaries = def.MitigationPolicy.BlockNonMicrosoftBinaries
	}
	return c
}

// defaultCompatibilityForRuntime returns the baseline Compatibility a
// tool inherits when its profile omits the `compatibility:` block.
// Bun-runtime tools (Claude Code, Bun CLI shipped as a SEA) need the
// per-session TEMP and the handle-list allowlist on; the other two
// fields default to "permissive" everywhere because no dizgin mitigation
// policy currently enforces them.
func defaultCompatibilityForRuntime(runtime string) Compatibility {
	t := true
	f := false
	base := Compatibility{
		TempOverride:        &t,
		HandleListAllowlist: &t,
		AllowDynamicCode:    &t,
		AllowLowLabelImages: &t,
		MitigationPolicy: &MitigationPolicy{
			// Off by default — opt-in only via profile. The restricted
			// backend's DefaultPolicies() also reads false here; the
			// nested struct exists so a profile can flip it to true.
			BlockNonMicrosoftBinaries: &f,
		},
	}
	switch runtime {
	case "bun":
		// Explicit acknowledgment that Bun SEA needs both — even
		// though the bool is the same as the universal default,
		// the case is preserved so the intent is documented in
		// the code (and a future hardening pass that flips the
		// universal default to OFF still keeps Bun working).
		return base
	default:
		return base
	}
}

// NeedsNPMCache returns true if the tool's runtime requires npm/node cache access.
func (t ToolDef) NeedsNPMCache() bool {
	switch t.Runtime {
	case "nodejs", "bun", "node", "electron":
		return true
	default:
		return false
	}
}

// IsExcluded reports whether the given path or env key appears in ExcludeDefaults.
func (t ToolDef) IsExcluded(s string) bool {
	for _, excl := range t.ExcludeDefaults {
		if excl == s {
			return true
		}
	}
	return false
}
