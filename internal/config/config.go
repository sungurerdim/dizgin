// SPDX-License-Identifier: MIT

// Package config defines configuration structs and the YAML loader for dizgin.
package config

import "time"

// NetworkPolicy controls outbound network access from the sandbox.
type NetworkPolicy string

const (
	NetworkOpen      NetworkPolicy = "open"
	NetworkAllowlist NetworkPolicy = "allowlist"
	NetworkBlocked   NetworkPolicy = "blocked"
)

// Config is the top-level configuration for a dizgin session.
type Config struct {
	Tools      map[string]ToolDef `mapstructure:"tools"      yaml:"tools"`
	Credential CredentialConfig   `mapstructure:"credential" yaml:"credential"`
	Monitor    MonitorConfig      `mapstructure:"monitor"    yaml:"monitor"`
	Tool       string             `mapstructure:"tool"       yaml:"tool"`
	Workdir    string             `mapstructure:"workdir"    yaml:"workdir"`
	Privileges PrivilegeConfig    `mapstructure:"privileges" yaml:"privileges"`
	Filesystem FilesystemConfig   `mapstructure:"filesystem" yaml:"filesystem"`
	Network    NetworkConfig      `mapstructure:"network"    yaml:"network"`
	Resources  ResourceConfig     `mapstructure:"resources"  yaml:"resources"`
	Audit      AuditConfig        `mapstructure:"audit"      yaml:"audit"`
	Setup      SetupConfig        `mapstructure:"setup"      yaml:"setup"`
	Version    int                `mapstructure:"version"    yaml:"version"`
	Security   SecurityConfig     `mapstructure:"security"   yaml:"security"`
}

// SetupConfig holds first-run dizgind configuration.
//
// The legacy ImageStoreDir + FoDs fields were removed in 2026-05-02
// when the HCS Hyper-V backend was retired — the iter6 restricted
// backend uses neither a base image nor a layer cache.
type SetupConfig struct {
	// Debug, when true, enables the verbose diagnostic framework for
	// every dizgin / dizgind invocation that loads this config —
	// equivalent to exporting DIZGIN_DEBUG=1 in the environment. Mirrors
	// the env switch so users that want verbose by default can persist
	// the choice in ~/.dizgin/config.yaml without leaking it into other
	// shells. DIZGIN_DEBUG=all (cross-process propagation) is intentionally
	// kept env-only — propagation is an opt-in for one debugging
	// session, not a persistent setting.
	Debug bool `mapstructure:"debug" yaml:"debug"`
}

// MonitorConfig controls resource metrics collection for sandboxed sessions.
type MonitorConfig struct {
	// Level sets the depth of metrics collection: "basic", "detailed", or "full".
	// Default: "basic".
	Level string `mapstructure:"level" yaml:"level"`
	// Interval is the collection interval (e.g. "10s", "5s" in YAML).
	// Default: 10s. Same shape as Resources.Timeout — both decode through
	// viper's default StringToTimeDurationHookFunc.
	Interval time.Duration `mapstructure:"interval" yaml:"interval"`
}

// FilesystemConfig controls which paths are visible inside the sandbox.
type FilesystemConfig struct {
	TmpSize     string   `mapstructure:"tmp_size" yaml:"tmp_size"`
	ReadWrite   []string `mapstructure:"read_write" yaml:"read_write"`
	ReadOnly    []string `mapstructure:"read_only" yaml:"read_only"`
	ZeroResidue bool     `mapstructure:"zero_residue" yaml:"zero_residue"`
}

// NetworkConfig controls outbound network access.
type NetworkConfig struct {
	Policy    NetworkPolicy `mapstructure:"policy"    yaml:"policy"`
	Allowlist []string      `mapstructure:"allowlist" yaml:"allowlist"`
}

// SecurityConfig holds security-related flags.
//
// All fields are Linux-only. The Windows restricted backend (restricted
// token + Medium IL) and macOS Seatbelt achieve the same outcome (no
// privilege gain, capability set empty) natively at sandbox creation
// time, so these flags are no-ops on those platforms. Kept in config
// so a single YAML file works across all hosts.
type SecurityConfig struct {
	// NoNewPrivileges prevents the sandboxed process from gaining new
	// privileges (Linux PR_SET_NO_NEW_PRIVS). On Linux, bwrap's
	// --unshare-user already provides this; on Windows / macOS the field is
	// a no-op.
	NoNewPrivileges bool `mapstructure:"no_new_privileges" yaml:"no_new_privileges"`
	// DropAllCaps drops all Linux capabilities. On Linux, --unshare-user
	// already yields cap=0 inside the new namespace; on Windows / macOS the
	// field is a no-op.
	DropAllCaps bool `mapstructure:"drop_all_caps" yaml:"drop_all_caps"`
}

// ResourceConfig limits CPU, memory, and PIDs inside the sandbox.
type ResourceConfig struct {
	// MemoryMB is the maximum resident memory in mebibytes (0 = unlimited).
	MemoryMB int `mapstructure:"memory_mb" yaml:"memory_mb"`
	// CPUPercent is the CPU share limit (0-100, 0 = unlimited).
	CPUPercent int `mapstructure:"cpu_percent" yaml:"cpu_percent"`
	// MaxPIDs limits the number of processes inside the sandbox (0 = unlimited).
	MaxPIDs int `mapstructure:"max_pids" yaml:"max_pids"`
	// Timeout terminates the session after this duration (0 = no timeout).
	Timeout time.Duration `mapstructure:"timeout" yaml:"timeout"`
}

// PrivilegeConfig controls privilege dropping behaviour.
type PrivilegeConfig struct {
	// RunAsUser is the user account to run the sandboxed process as (empty = current).
	RunAsUser string `mapstructure:"run_as_user" yaml:"run_as_user"`
}

// CredentialConfig controls which host credentials are forwarded into the sandbox.
type CredentialConfig struct {
	VaultMount  string   `mapstructure:"vault_mount" yaml:"vault_mount"`
	VaultPath   string   `mapstructure:"vault_path" yaml:"vault_path"`
	APIKeys     []string `mapstructure:"api_keys" yaml:"api_keys"`
	Providers   []string `mapstructure:"providers" yaml:"providers"`
	SSHAgent    bool     `mapstructure:"ssh_agent" yaml:"ssh_agent"`
	GitIdentity bool     `mapstructure:"git_identity" yaml:"git_identity"`
	GitHubToken bool     `mapstructure:"github_token" yaml:"github_token"`
}

// AuditConfig controls the optional audit log.
type AuditConfig struct {
	// Enabled enables JSON-L audit logging (default: false, opt-in).
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
	// MaxSizeMB is the maximum audit log file size in MiB before rotation (0 = unlimited).
	MaxSizeMB int `mapstructure:"max_size_mb" yaml:"max_size_mb"`
}

// Tool describes a named AI coding tool with its default mount map.
type Tool struct {
	Name      string   `mapstructure:"name"       yaml:"name"`
	Binary    string   `mapstructure:"binary"     yaml:"binary"`
	ExtraDirs []string `mapstructure:"extra_dirs" yaml:"extra_dirs"`
}
