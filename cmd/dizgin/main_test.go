// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sungurerdim/dizgin/internal/credential"
)

// ── parseOwnFlags ─────────────────────────────────────────────────────────────

// resetGlobals saves and restores package-level flag variables around a test.
func resetGlobals(t *testing.T) {
	t.Helper()
	oldW, oldC, oldN := workdir, configFile, noTTY
	t.Cleanup(func() { workdir, configFile, noTTY = oldW, oldC, oldN })
	workdir, configFile, noTTY = "", "", false
}

func TestParseOwnFlags_WorkdirShort(t *testing.T) {
	resetGlobals(t)
	rem := parseOwnFlags([]string{"-w", "/proj", "claude"})
	if workdir != "/proj" {
		t.Errorf("workdir: got %q, want /proj", workdir)
	}
	if len(rem) != 1 || rem[0] != "claude" {
		t.Errorf("remaining: got %v, want [claude]", rem)
	}
}

func TestParseOwnFlags_NoTTY(t *testing.T) {
	resetGlobals(t)
	rem := parseOwnFlags([]string{"--no-pty", "echo", "hi"})
	if !noTTY {
		t.Error("noTTY should be true after --no-pty")
	}
	if len(rem) != 2 || rem[0] != "echo" {
		t.Errorf("remaining: got %v, want [echo hi]", rem)
	}
}

func TestParseOwnFlags_MixedFlags(t *testing.T) {
	resetGlobals(t)
	rem := parseOwnFlags([]string{"-w", "/proj", "-c", "my.yaml", "--no-pty", "KEY=val", "tool"})
	if workdir != "/proj" {
		t.Errorf("workdir: got %q", workdir)
	}
	if configFile != "my.yaml" {
		t.Errorf("configFile: got %q", configFile)
	}
	if !noTTY {
		t.Error("noTTY should be true")
	}
	if len(rem) != 2 || rem[0] != "KEY=val" || rem[1] != "tool" {
		t.Errorf("remaining: got %v, want [KEY=val tool]", rem)
	}
}

func TestParseOwnFlags_EqualsStyle(t *testing.T) {
	resetGlobals(t)
	rem := parseOwnFlags([]string{"-w=/proj", "-c=my.yaml", "tool"})
	if workdir != "/proj" {
		t.Errorf("workdir: got %q", workdir)
	}
	if configFile != "my.yaml" {
		t.Errorf("configFile: got %q", configFile)
	}
	if len(rem) != 1 || rem[0] != "tool" {
		t.Errorf("remaining: got %v", rem)
	}
}

// ── parseArgs ──────────────────────────────────────────────────────────────────

func TestParseArgs_EnvThenTool(t *testing.T) {
	tool, env := parseArgs([]string{"KEY=val", "mytool", "--flag"})
	if len(tool) != 2 || tool[0] != "mytool" || tool[1] != "--flag" {
		t.Errorf("toolArgs: got %v, want [mytool --flag]", tool)
	}
	if len(env) != 1 || env[0] != "KEY=val" {
		t.Errorf("envOverrides: got %v, want [KEY=val]", env)
	}
}

func TestParseArgs_MultipleEnvOverrides(t *testing.T) {
	tool, env := parseArgs([]string{"A=1", "B=2", "cmd"})
	if len(tool) != 1 || tool[0] != "cmd" {
		t.Errorf("toolArgs: got %v", tool)
	}
	if len(env) != 2 {
		t.Errorf("envOverrides: got %v, want [A=1 B=2]", env)
	}
}

func TestParseArgs_ToolWithFlags(t *testing.T) {
	tool, env := parseArgs([]string{"claude", "--help"})
	if len(tool) != 2 || tool[0] != "claude" || tool[1] != "--help" {
		t.Errorf("toolArgs: got %v, want [claude --help]", tool)
	}
	if len(env) != 0 {
		t.Errorf("envOverrides: got %v, want []", env)
	}
}

// ── isEnvOverride ──────────────────────────────────────────────────────────────

func TestIsEnvOverride(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"KEY=val", true},
		{"_UNDER=x", true},
		{"A=", true},        // empty value is valid
		{"=val", false},     // no key
		{"1KEY=val", false}, // starts with digit
		{"KEY", false},      // no equals
		{"key=val", true},   // lowercase allowed
	}
	for _, c := range cases {
		if got := isEnvOverride(c.in); got != c.want {
			t.Errorf("isEnvOverride(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// ── buildToolEnv ───────────────────────────────────────────────────────────────

func TestBuildToolEnvOverride(t *testing.T) {
	orig := os.Environ()
	defer func() {
		os.Clearenv()
		for _, kv := range orig {
			idx := strings.IndexByte(kv, '=')
			if idx > 0 {
				_ = os.Setenv(kv[:idx], kv[idx+1:])
			}
		}
	}()
	os.Clearenv()
	if err := os.Setenv("EXISTING", "old"); err != nil {
		t.Fatal(err)
	}

	creds := []credential.Credential{
		{Key: "EXISTING", Value: "new"},
		{Key: "ADDED", Value: "yes"},
	}
	result := buildToolEnv(creds, nil, "")

	m := make(map[string]string)
	for _, kv := range result {
		idx := strings.IndexByte(kv, '=')
		if idx > 0 {
			m[kv[:idx]] = kv[idx+1:]
		}
	}
	if m["EXISTING"] != "new" {
		t.Errorf("EXISTING: got %q, want %q", m["EXISTING"], "new")
	}
	if m["ADDED"] != "yes" {
		t.Errorf("ADDED: got %q, want %q", m["ADDED"], "yes")
	}
}

// ── loadConfig ─────────────────────────────────────────────────────────────────

func TestLoadConfigFromWorkdir(t *testing.T) {
	wd := t.TempDir()
	cfgPath := filepath.Join(wd, "dizgin.yaml")
	if err := os.WriteFile(cfgPath, []byte("version: 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(wd)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Version != 1 {
		t.Errorf("version: got %d, want 1", cfg.Version)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := loadConfig(t.TempDir())
	if err != nil {
		t.Fatalf("loadConfig defaults: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
}

// ── resolveWorkdir ─────────────────────────────────────────────────────────────

// ── parseArgs edge cases ────────────────────────────────────────────────────

func TestParseArgs_EmptyArgs(t *testing.T) {
	tool, env := parseArgs(nil)
	if tool != nil {
		t.Errorf("toolArgs: got %v, want nil", tool)
	}
	if env != nil {
		t.Errorf("envOverrides: got %v, want nil", env)
	}
}

func TestParseArgs_OnlyEnvOverrides(t *testing.T) {
	tool, env := parseArgs([]string{"A=1", "B=2"})
	if tool != nil {
		t.Errorf("toolArgs: got %v, want nil", tool)
	}
	if len(env) != 2 || env[0] != "A=1" || env[1] != "B=2" {
		t.Errorf("envOverrides: got %v, want [A=1 B=2]", env)
	}
}

// ── isEnvOverride edge cases ────────────────────────────────────────────────

func TestIsEnvOverride_DigitOnlyKey(t *testing.T) {
	if isEnvOverride("123=value") {
		t.Error("isEnvOverride(\"123=value\") = true, want false")
	}
}

// ── isInfoCommand ────────────────────────────────────────────────────────────

// TestIsInfoCommand_KnownCommands is a regression test for the daemon
// autostart gate: every command listed here must NOT trigger dizgind
// autostart (e.g. `dizgin --version` should never spawn the daemon).
func TestIsInfoCommand_KnownCommands(t *testing.T) {
	for _, args := range [][]string{
		{"-h"}, {"--help"}, {"-v"}, {"--version"},
		{"version"}, {"completion", "bash"}, {"doctor"},
		{"add-path", "/tmp/x"}, {"diagnose-hang"}, {"update"},
	} {
		if !isInfoCommand(args) {
			t.Errorf("isInfoCommand(%v) = false, want true", args)
		}
	}
}

func TestIsInfoCommand_ToolInvocationIsNotInfo(t *testing.T) {
	if isInfoCommand([]string{"claude"}) {
		t.Error("isInfoCommand([\"claude\"]) = true, want false — a real tool invocation must autostart the daemon")
	}
}

func TestIsInfoCommand_EmptyArgs(t *testing.T) {
	if isInfoCommand(nil) {
		t.Error("isInfoCommand(nil) = true, want false")
	}
}

// ── resolveWorkdir ──────────────────────────────────────────────────────────

func TestResolveWorkdirRelative(t *testing.T) {
	// A relative path should be resolved to an absolute path.
	wd, err := resolveWorkdir("relative/path")
	if err != nil {
		t.Fatalf("resolveWorkdir: %v", err)
	}
	if !filepath.IsAbs(wd) {
		t.Errorf("expected absolute path, got %q", wd)
	}
	if !strings.HasSuffix(wd, filepath.Join("relative", "path")) {
		t.Errorf("expected path ending in relative/path, got %q", wd)
	}
}

func TestResolveWorkdirAbsolute(t *testing.T) {
	tmp := t.TempDir()
	wd, err := resolveWorkdir(tmp)
	if err != nil {
		t.Fatalf("resolveWorkdir: %v", err)
	}
	// On Windows, EvalSymlinks may normalize the path casing, so compare
	// using filepath.Clean on both sides.
	if filepath.Clean(wd) != filepath.Clean(tmp) {
		t.Errorf("expected %q, got %q", tmp, wd)
	}
}

// ── loadConfig edge cases ───────────────────────────────────────────────────

func TestLoadConfigNonExistentFile(t *testing.T) {
	// Set the package-level configFile to trigger the --config path in loadConfig.
	old := configFile
	configFile = filepath.Join(t.TempDir(), "does-not-exist.yaml")
	defer func() { configFile = old }()

	_, err := loadConfig(t.TempDir())
	if err == nil {
		t.Fatal("expected error for non-existent config file")
	}
	if !strings.Contains(err.Error(), "does-not-exist.yaml") {
		t.Errorf("error should reference the file name, got: %v", err)
	}
}

func TestLoadConfigEmptyWorkdir(t *testing.T) {
	// Empty workdir (no config file present) should return defaults.
	cfg, err := loadConfig("")
	if err != nil {
		t.Fatalf("loadConfig with empty workdir: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
}

func TestResolveWorkdirEmpty(t *testing.T) {
	wd, err := resolveWorkdir("")
	if err != nil {
		t.Fatalf("resolveWorkdir: %v", err)
	}
	if !filepath.IsAbs(wd) {
		t.Errorf("expected absolute path, got %q", wd)
	}
}

func TestResolveWorkdirExplicit(t *testing.T) {
	tmp := t.TempDir()
	wd, err := resolveWorkdir(tmp)
	if err != nil {
		t.Fatalf("resolveWorkdir: %v", err)
	}
	if !filepath.IsAbs(wd) {
		t.Errorf("expected absolute path, got %q", wd)
	}
}
