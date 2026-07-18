// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\") error: %v", err)
	}

	if cfg.Version != 1 {
		t.Errorf("default version: got %d, want 1", cfg.Version)
	}
	if cfg.Filesystem.TmpSize != "256m" {
		t.Errorf("default tmp_size: got %q, want %q", cfg.Filesystem.TmpSize, "256m")
	}
	if cfg.Network.Policy != NetworkOpen {
		t.Errorf("default network.policy: got %q, want %q", cfg.Network.Policy, NetworkOpen)
	}
	if !cfg.Security.NoNewPrivileges {
		t.Error("default security.no_new_privileges: got false, want true")
	}
	if !cfg.Security.DropAllCaps {
		t.Error("default security.drop_all_caps: got false, want true")
	}
	if !cfg.Credential.SSHAgent {
		t.Error("default credential.ssh_agent: got false, want true")
	}
	if !cfg.Credential.GitIdentity {
		t.Error("default credential.git_identity: got false, want true")
	}
	if !cfg.Credential.GitHubToken {
		t.Error("default credential.github_token: got false, want true")
	}
}

func TestLoadFromFile(t *testing.T) {
	yaml := `
version: 1
tool: claude
workdir: /tmp/proj
filesystem:
  tmp_size: 512m
  zero_residue: true
network:
  policy: blocked
security:
  no_new_privileges: true
  drop_all_caps: false
resources:
  memory_mb: 1024
  cpu_percent: 50
  max_pids: 100
credential:
  ssh_agent: false
  git_identity: true
  github_token: false
`
	f := filepath.Join(t.TempDir(), "dizgin.yaml")
	if err := os.WriteFile(f, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(f)
	if err != nil {
		t.Fatalf("Load(%q) error: %v", f, err)
	}

	if cfg.Tool != "claude" {
		t.Errorf("tool: got %q, want %q", cfg.Tool, "claude")
	}
	if cfg.Filesystem.TmpSize != "512m" {
		t.Errorf("tmp_size: got %q, want %q", cfg.Filesystem.TmpSize, "512m")
	}
	if !cfg.Filesystem.ZeroResidue {
		t.Error("zero_residue: got false, want true")
	}
	if cfg.Network.Policy != NetworkBlocked {
		t.Errorf("network.policy: got %q, want %q", cfg.Network.Policy, NetworkBlocked)
	}
	if cfg.Resources.MemoryMB != 1024 {
		t.Errorf("memory_mb: got %d, want 1024", cfg.Resources.MemoryMB)
	}
	if cfg.Resources.CPUPercent != 50 {
		t.Errorf("cpu_percent: got %d, want 50", cfg.Resources.CPUPercent)
	}
	if cfg.Resources.MaxPIDs != 100 {
		t.Errorf("max_pids: got %d, want 100", cfg.Resources.MaxPIDs)
	}
	if cfg.Credential.SSHAgent {
		t.Error("credential.ssh_agent: got true, want false")
	}
}

func TestValidationErrors(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name:    "bad version",
			mutate:  func(c *Config) { c.Version = 99 },
			wantErr: "unsupported config version",
		},
		{
			name:    "unknown network policy",
			mutate:  func(c *Config) { c.Network.Policy = "random" },
			wantErr: "unknown network.policy",
		},
		{
			name: "allowlist without entries",
			mutate: func(c *Config) {
				c.Network.Policy = NetworkAllowlist
				c.Network.Allowlist = nil
			},
			wantErr: "requires at least one entry",
		},
		{
			name:    "cpu_percent out of range",
			mutate:  func(c *Config) { c.Resources.CPUPercent = 200 },
			wantErr: "cpu_percent must be 0-100",
		},
		{
			name:    "negative memory_mb",
			mutate:  func(c *Config) { c.Resources.MemoryMB = -1 },
			wantErr: "memory_mb must be >= 0",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _ := Load("")
			tc.mutate(cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if got := err.Error(); !contains(got, tc.wantErr) {
				t.Errorf("error %q does not contain %q", got, tc.wantErr)
			}
		})
	}
}

// seedTestProfiles injects test profiles so tests don't depend on disk files.
func seedTestProfiles() {
	SetProfiles(map[string]ToolDef{
		"claude": {
			ConfigDirs:  []string{"~/.claude"},
			EnvKeys:     []string{"ANTHROPIC_API_KEY"},
			DefaultArgs: []string{"--dangerously-skip-permissions"},
			Runtime:     "bun",
		},
		"aider": {
			ConfigDirs: []string{"~/.aider"},
			EnvKeys:    []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY"},
		},
		"codex": {
			ConfigDirs: []string{"~/.codex"},
			EnvKeys:    []string{"OPENAI_API_KEY"},
		},
	})
}

func TestLookupTool_Profile(t *testing.T) {
	seedTestProfiles()
	def := LookupTool("claude")
	if len(def.ConfigDirs) == 0 {
		t.Error("claude ConfigDirs should not be empty")
	}
	if len(def.EnvKeys) == 0 {
		t.Error("claude EnvKeys should not be empty")
	}
	foundAnthropicKey := false
	for _, k := range def.EnvKeys {
		if k == "ANTHROPIC_API_KEY" {
			foundAnthropicKey = true
		}
	}
	if !foundAnthropicKey {
		t.Errorf("claude EnvKeys should contain ANTHROPIC_API_KEY, got %v", def.EnvKeys)
	}
}

func TestLookupTool_Normalize(t *testing.T) {
	seedTestProfiles()
	def := LookupTool("Claude.exe")
	if len(def.EnvKeys) == 0 {
		t.Error("LookupTool(\"Claude.exe\") should return non-empty EnvKeys")
	}
}

func TestKnownToolNames(t *testing.T) {
	seedTestProfiles()
	names := KnownToolNames()
	required := []string{"claude", "aider", "codex"}
	nameSet := make(map[string]bool, len(names))
	for _, n := range names {
		nameSet[n] = true
	}
	for _, req := range required {
		if !nameSet[req] {
			t.Errorf("KnownToolNames() missing %q, got %v", req, names)
		}
	}
}

func TestNormalizeName(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"claude", "claude"},
		{"Claude.exe", "claude"},
		{"AIDER.EXE", "aider"},
		{"/usr/local/bin/codex", "codex"},
	}
	if runtime.GOOS == "windows" {
		// filepath.Base only splits on backslash where it is a separator.
		cases = append(cases, struct {
			input string
			want  string
		}{"C:\\Program Files\\tool.exe", "tool"})
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := normalizeName(tc.input)
			if got != tc.want {
				t.Errorf("normalizeName(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestExpandPath(t *testing.T) {
	cases := []struct {
		name string
		path string
		home string
		want string
	}{
		{
			name: "tilde prefix",
			path: "~/.claude",
			home: "/home/user",
			want: filepath.Join("/home/user", ".claude"),
		},
		{
			name: "tilde only",
			path: "~",
			home: "/home/user",
			want: "/home/user",
		},
		{
			name: "empty home with tilde",
			path: "~/.config",
			home: "",
			want: "~/.config",
		},
		{
			name: "plain path unchanged",
			path: "/etc/config",
			home: "/home/user",
			want: "/etc/config",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := expandPath(tc.path, tc.home)
			if got != tc.want {
				t.Errorf("expandPath(%q, %q) = %q, want %q", tc.path, tc.home, got, tc.want)
			}
		})
	}
}

func TestNPMCacheDir(t *testing.T) {
	t.Run("with env var", func(t *testing.T) {
		t.Setenv("npm_config_cache", "/custom/npm-cache")
		got := NPMCacheDir()
		if got != "/custom/npm-cache" {
			t.Errorf("NPMCacheDir() = %q, want %q", got, "/custom/npm-cache")
		}
	})

	t.Run("without env var", func(t *testing.T) {
		t.Setenv("npm_config_cache", "")
		got := NPMCacheDir()
		if got == "" {
			t.Error("NPMCacheDir() should not be empty when env var is unset")
		}
	})
}

func TestAutoDetectTool(t *testing.T) {
	t.Setenv("MYTOOL_API_KEY", "sk-test-123")
	def := autoDetectTool("mytool")

	foundKey := false
	for _, k := range def.EnvKeys {
		if k == "MYTOOL_API_KEY" {
			foundKey = true
		}
	}
	if !foundKey {
		t.Errorf("autoDetectTool should detect MYTOOL_API_KEY, got %v", def.EnvKeys)
	}
}

func TestValidation_MaxPids(t *testing.T) {
	cfg, _ := Load("")
	cfg.Resources.MaxPIDs = -5
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for negative max_pids, got nil")
	}
	if !contains(err.Error(), "max_pids must be >= 0") {
		t.Errorf("error %q does not mention max_pids", err.Error())
	}
}

func TestValidation_Timeout(t *testing.T) {
	cfg, _ := Load("")
	cfg.Resources.Timeout = -1 * time.Second
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for negative timeout, got nil")
	}
	if !contains(err.Error(), "timeout must be >= 0") {
		t.Errorf("error %q does not mention timeout", err.Error())
	}
}

func TestValidation_MonitorLevel(t *testing.T) {
	cfg, _ := Load("")
	cfg.Monitor.Level = "ultra"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for invalid monitor level, got nil")
	}
	if !contains(err.Error(), "monitor.level must be") {
		t.Errorf("error %q does not mention monitor.level", err.Error())
	}
}

func TestValidation_MonitorInterval(t *testing.T) {
	cfg, _ := Load("")
	cfg.Monitor.Interval = -1 * time.Second
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for negative monitor interval, got nil")
	}
	if !contains(err.Error(), "monitor.interval must be >= 0") {
		t.Errorf("error %q does not mention monitor.interval", err.Error())
	}
}

// TestLoadFromFile_InvalidMonitorInterval covers the case the type change
// (string -> time.Duration) moved earlier: a malformed duration in the YAML
// file now fails at Load() (viper's decode hook), not at Validate().
func TestLoadFromFile_InvalidMonitorInterval(t *testing.T) {
	yaml := `
version: 1
monitor:
  interval: not-a-duration
`
	f := filepath.Join(t.TempDir(), "dizgin.yaml")
	if err := os.WriteFile(f, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(f)
	if err == nil {
		t.Fatal("expected Load to fail for a malformed monitor.interval duration, got nil")
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub)))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
