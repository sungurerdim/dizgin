// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/config"
	"github.com/sungurerdim/dizgin/internal/credential"
	"github.com/sungurerdim/dizgin/internal/monitor"
	"github.com/sungurerdim/dizgin/internal/sandbox"
)

// ── buildMounts ──────────────────────────────────────────────────────────────

func TestBuildMounts_BasicWorkdir(t *testing.T) {
	wd := "/project"
	if runtime.GOOS == "windows" {
		wd = `C:\project`
	}
	def := config.ToolDef{}
	mounts := buildMounts(wd, def, "")

	// Should have at least the workdir mount.
	if len(mounts) < 1 {
		t.Fatalf("expected at least 1 mount, got %d", len(mounts))
	}
	if mounts[0].Host != wd {
		t.Errorf("workdir mount host: %q, want %q", mounts[0].Host, wd)
	}
	if mounts[0].Guest != wd {
		t.Errorf("workdir mount guest: %q, want %q", mounts[0].Guest, wd)
	}
	if mounts[0].ReadOnly {
		t.Error("workdir mount should be read-write")
	}
}

func TestBuildMounts_WithToolPath(t *testing.T) {
	var wd, toolPath string
	if runtime.GOOS == "windows" {
		wd = `C:\project`
		toolPath = `C:\tools\bin\claude.exe`
	} else {
		wd = "/project"
		toolPath = "/usr/local/bin/claude"
	}

	def := config.ToolDef{}
	mounts := buildMounts(wd, def, toolPath)

	// Should have workdir + tool binary dir.
	if len(mounts) < 2 {
		t.Fatalf("expected at least 2 mounts, got %d", len(mounts))
	}

	binDir := filepath.Dir(toolPath)
	found := false
	for _, m := range mounts {
		if m.Host == binDir && m.ReadOnly {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected read-only mount for tool binary dir %q", binDir)
	}
}

func TestBuildMounts_EmptyToolPath(t *testing.T) {
	wd := "/project"
	if runtime.GOOS == "windows" {
		wd = `C:\project`
	}
	def := config.ToolDef{}
	mounts := buildMounts(wd, def, "")

	// Should have at least the workdir mount.
	// Additional R/O mounts from DefaultToolDeps and host PATH are expected.
	if len(mounts) < 1 {
		t.Fatalf("expected at least 1 mount, got %d", len(mounts))
	}
	// Workdir must be the first mount and must be R/W.
	if mounts[0].Host != wd || mounts[0].ReadOnly {
		t.Errorf("first mount must be the R/W workdir, got host=%q ro=%v", mounts[0].Host, mounts[0].ReadOnly)
	}
}

// ── addToolDepMounts / addLibDepMounts ──────────────────────────────────────

func TestAddToolDepMounts_ReadWrite(t *testing.T) {
	dir := t.TempDir()
	def := config.ToolDef{ToolDeps: []string{dir}}
	m := newMountAppender(4)
	addToolDepMounts(m, def)
	mounts := m.result()

	found := false
	for _, mt := range mounts {
		if mt.Host == dir && !mt.ReadOnly && mt.Category == sandbox.CategoryDeclaredRW {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected DeclaredRW mount for tool_dep dir %q, got %v", dir, mounts)
	}
}

func TestAddLibDepMounts_ReadOnly(t *testing.T) {
	dir := t.TempDir()
	def := config.ToolDef{LibDeps: []string{dir}}
	m := newMountAppender(4)
	addLibDepMounts(m, def)
	mounts := m.result()

	found := false
	for _, mt := range mounts {
		if mt.Host == dir && mt.ReadOnly && mt.Category == sandbox.CategoryDeclaredRO {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected DeclaredRO mount for lib_dep dir %q, got %v", dir, mounts)
	}
}

func TestAddLibDepMounts_DeprecatedRuntimeDirs(t *testing.T) {
	dir := t.TempDir()
	def := config.ToolDef{RuntimeDirs: []string{dir}}
	m := newMountAppender(4)
	addLibDepMounts(m, def)
	mounts := m.result()

	found := false
	for _, mt := range mounts {
		if mt.Host == dir && mt.ReadOnly {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("deprecated runtime_dirs entry should produce R/O mount for %q, got %v", dir, mounts)
	}
}

// ── addMCPDirMounts ──────────────────────────────────────────────────────────

func TestAddMCPDirMounts_ProfileDirMounted(t *testing.T) {
	dir := t.TempDir()
	def := config.ToolDef{MCPDirs: []string{dir}}
	m := newMountAppender(4)
	addMCPDirMounts(m, def)
	mounts := m.result()

	found := false
	for _, mt := range mounts {
		if mt.Host == dir && !mt.ReadOnly && mt.Category == sandbox.CategoryDeclaredRW {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected DeclaredRW mount for mcp_dirs entry %q, got %v", dir, mounts)
	}
}

func TestAddMCPDirMounts_EmptyDirSkipped(t *testing.T) {
	def := config.ToolDef{MCPDirs: []string{"/nonexistent/mcp-test-path-xyz"}}
	m := newMountAppender(4)
	addMCPDirMounts(m, def)
	mounts := m.result()
	for _, mt := range mounts {
		if mt.Host == "/nonexistent/mcp-test-path-xyz" {
			t.Errorf("non-existent MCP dir should not produce a mount, got %v", mt)
		}
	}
}

// ── sanitizeMountPath ────────────────────────────────────────────────────────

func TestSanitizeMountPath_Clean(t *testing.T) {
	var input, want string
	if runtime.GOOS == "windows" {
		input = `C:\tools\bin`
		want = `C:\tools\bin`
	} else {
		input = "/usr/local/bin"
		want = "/usr/local/bin"
	}
	got := sanitizeMountPath(input)
	if got != want {
		t.Errorf("sanitizeMountPath(%q) = %q, want %q", input, got, want)
	}
}

func TestSanitizeMountPath_Traversal(t *testing.T) {
	// On Windows, filepath.Clean resolves "/safe/../../etc/passwd" to "\etc\passwd"
	// (no ".." remains), so the traversal check doesn't trigger.
	// Use a path that retains ".." after cleaning on all platforms.
	got := sanitizeMountPath("../../../etc/passwd")
	if got != "" {
		t.Errorf("expected empty for traversal path, got %q", got)
	}
}

func TestSanitizeMountPath_DotDotMiddle(t *testing.T) {
	got := sanitizeMountPath("/a/b/../c")
	// filepath.Clean resolves this to /a/c, which has no ".." parts.
	if got == "" {
		t.Error("expected non-empty for resolvable ../")
	}
}

// ── buildToolEnv ─────────────────────────────────────────────────────────────

func TestBuildToolEnv_InjectsTerminalDefaults(t *testing.T) {
	// Unset terminal vars so we can verify defaults are injected when absent.
	for _, key := range []string{"TERM", "COLORTERM", "FORCE_COLOR", "COLUMNS", "LINES"} {
		orig, had := os.LookupEnv(key)
		os.Unsetenv(key) //nolint:errcheck
		if had {
			t.Cleanup(func() { os.Setenv(key, orig) }) //nolint:errcheck
		} else {
			t.Cleanup(func() { os.Unsetenv(key) }) //nolint:errcheck
		}
	}

	result := buildToolEnv(nil, nil, "")

	// TERM, COLORTERM, FORCE_COLOR are always injected with known defaults.
	wantDefaults := map[string]string{
		"TERM":        "xterm-256color",
		"COLORTERM":   "truecolor",
		"FORCE_COLOR": "3",
	}
	found := make(map[string]string, len(result))
	for _, kv := range result {
		k, v := credential.SplitKV(kv)
		found[k] = v
	}
	for k, wantV := range wantDefaults {
		if got, ok := found[k]; !ok {
			t.Errorf("expected %s to be injected when absent from host env", k)
		} else if got != wantV {
			t.Errorf("%s: got %q, want %q", k, got, wantV)
		}
	}

	// COLUMNS and LINES are injected when the host terminal reports a size.
	// In test environments (no real TTY), currentTerminalSize returns (0,0,false)
	// and they are omitted — verify they are not set to garbage values.
	if colsStr, ok := found["COLUMNS"]; ok {
		var cols int
		if _, err := fmt.Sscanf(colsStr, "%d", &cols); err != nil || cols <= 0 {
			t.Errorf("COLUMNS injected with invalid value %q", colsStr)
		}
	}
	if linesStr, ok := found["LINES"]; ok {
		var lines int
		if _, err := fmt.Sscanf(linesStr, "%d", &lines); err != nil || lines <= 0 {
			t.Errorf("LINES injected with invalid value %q", linesStr)
		}
	}
}

func TestBuildToolEnv_RespectsExistingTERM(t *testing.T) {
	t.Setenv("TERM", "screen-256color")

	result := buildToolEnv(nil, nil, "")

	for _, kv := range result {
		k, v := credential.SplitKV(kv)
		if k == "TERM" {
			if v == "xterm-256color" {
				t.Error("should not override existing TERM with default")
			}
			if v != "screen-256color" {
				t.Errorf("TERM: got %q, want %q", v, "screen-256color")
			}
			return
		}
	}
	t.Error("TERM not found in result")
}

func TestBuildToolEnv_CliOverridesTakesPrecedence(t *testing.T) {
	creds := []credential.Credential{
		{Key: "API_KEY", Value: "from-creds"},
	}
	overrides := []string{"API_KEY=from-cli"}

	result := buildToolEnv(creds, overrides, "")
	if !slices.Contains(result, "API_KEY=from-cli") {
		t.Error("CLI override should take precedence over credential value")
	}
}

func TestBuildToolEnv_ScratchDirOverridesTemp(t *testing.T) {
	t.Setenv("TEMP", `C:\Users\Sungur\AppData\Local\Temp`)
	t.Setenv("TMP", `C:\Users\Sungur\AppData\Local\Temp`)
	t.Setenv(brand.Env("NO_TEMP_OVERRIDE"), "")
	const scratch = `C:\ProgramData\dizgin\appcontainer\dizgin-1234-567890`

	result := buildToolEnv(nil, nil, scratch)

	wantOverrides := map[string]string{
		"TEMP":   scratch,
		"TMP":    scratch,
		"TMPDIR": scratch,
	}
	got := make(map[string]string, len(result))
	for _, kv := range result {
		k, v := credential.SplitKV(kv)
		got[k] = v
	}
	for k, want := range wantOverrides {
		if v, ok := got[k]; !ok {
			t.Errorf("expected %s to be injected", k)
		} else if v != want {
			t.Errorf("%s: got %q, want %q", k, v, want)
		}
	}
}

func TestBuildToolEnv_OptOutPreservesHostTemp(t *testing.T) {
	const hostTemp = `C:\Users\Sungur\AppData\Local\Temp`
	t.Setenv("TEMP", hostTemp)
	t.Setenv(brand.Env("NO_TEMP_OVERRIDE"), "1")

	result := buildToolEnv(nil, nil, `C:\ProgramData\dizgin\appcontainer\dizgin-test`)

	for _, kv := range result {
		k, v := credential.SplitKV(kv)
		if k == "TEMP" && v != hostTemp {
			t.Errorf("opt-out should preserve host TEMP; got %q, want %q", v, hostTemp)
		}
	}
}

func TestBuildToolEnv_CLIOverrideBeatsScratchDir(t *testing.T) {
	const scratch = `C:\ProgramData\dizgin\appcontainer\dizgin-test`
	const userOverride = `D:\custom-temp`

	result := buildToolEnv(nil, []string{"TEMP=" + userOverride}, scratch)

	for _, kv := range result {
		k, v := credential.SplitKV(kv)
		if k == "TEMP" {
			if v != userOverride {
				t.Errorf("CLI override should beat scratch dir; got %q, want %q", v, userOverride)
			}
			return
		}
	}
	t.Error("TEMP not found in result")
}

func TestBuildToolEnv_NewKeysAdded(t *testing.T) {
	creds := []credential.Credential{
		{Key: "NEW_VAR_XYZ_TEST", Value: "hello"},
	}
	result := buildToolEnv(creds, nil, "")
	if !slices.Contains(result, "NEW_VAR_XYZ_TEST=hello") {
		t.Error("new credential key should be added to env")
	}
}

func TestBuildToolEnv_NewKeysSorted(t *testing.T) {
	creds := []credential.Credential{
		{Key: "ZZZ_KEY", Value: "z"},
		{Key: "AAA_KEY", Value: "a"},
	}
	result := buildToolEnv(creds, nil, "")

	// Find positions of the two new keys.
	aIdx, zIdx := -1, -1
	for i, kv := range result {
		if kv == "AAA_KEY=a" {
			aIdx = i
		}
		if kv == "ZZZ_KEY=z" {
			zIdx = i
		}
	}
	if aIdx == -1 || zIdx == -1 {
		t.Fatal("both keys should be present")
	}
	if aIdx >= zIdx {
		t.Error("AAA_KEY should come before ZZZ_KEY (sorted)")
	}
}

// ── buildSandboxOpts ─────────────────────────────────────────────────────────

// noopBackend is a minimal sandbox.Backend stub for tests that do not
// exercise the permission-profile load or stamp-progress paths. It does
// not implement optional interfaces (PermissionProfileLoader,
// StampProgressSetter) so those code paths take the graceful-fallback route.
type noopBackend struct{}

func (noopBackend) Name() string    { return "noop" }
func (noopBackend) Available() bool { return false }
func (noopBackend) Create(_ context.Context, _ *config.Config, _ sandbox.CreateOpts) (sandbox.Box, error) {
	return nil, nil
}

func TestBuildSandboxOpts_Fields(t *testing.T) {
	wd := "/project"
	if runtime.GOOS == "windows" {
		wd = `C:\project`
	}
	def := config.ToolDef{}
	creds := []sandbox.Credential{{Key: "K", Value: "V"}}
	cfg := &config.Config{
		Network: config.NetworkConfig{
			Policy:    config.NetworkBlocked,
			Allowlist: []string{"api.example.com"},
		},
		Resources: config.ResourceConfig{
			MemoryMB:   512,
			CPUPercent: 50,
			MaxPIDs:    100,
			Timeout:    30 * time.Second,
		},
	}

	opts := buildSandboxOpts(wd, def, "", creds, cfg, noopBackend{}, true, 220, 50)

	if opts.Workdir != wd {
		t.Errorf("Workdir: %q, want %q", opts.Workdir, wd)
	}
	if opts.Network != config.NetworkBlocked {
		t.Errorf("Network: %v, want %v", opts.Network, config.NetworkBlocked)
	}
	if len(opts.Allowlist) != 1 || opts.Allowlist[0] != "api.example.com" {
		t.Errorf("Allowlist: %v", opts.Allowlist)
	}
	if opts.Resources.MemoryMB != 512 {
		t.Errorf("MemoryMB: %d, want 512", opts.Resources.MemoryMB)
	}
	if opts.Resources.CPUPercent != 50 {
		t.Errorf("CPUPercent: %d, want 50", opts.Resources.CPUPercent)
	}
	if opts.Resources.MaxPIDs != 100 {
		t.Errorf("MaxPIDs: %d, want 100", opts.Resources.MaxPIDs)
	}
	if opts.Resources.Timeout != 30*time.Second {
		t.Errorf("Timeout: %v, want 30s", opts.Resources.Timeout)
	}
	if !opts.PTY {
		t.Error("PTY should be true")
	}
	if opts.InitialCols != 220 {
		t.Errorf("InitialCols: %d, want 220", opts.InitialCols)
	}
	if opts.InitialRows != 50 {
		t.Errorf("InitialRows: %d, want 50", opts.InitialRows)
	}
	if len(opts.Credentials) != 1 || opts.Credentials[0].Key != "K" {
		t.Errorf("Credentials: %v", opts.Credentials)
	}
}

// ── parseMonitorLevel ────────────────────────────────────────────────────────

func TestParseMonitorLevel(t *testing.T) {
	cases := []struct {
		in   string
		want monitor.Level
	}{
		{"basic", monitor.LevelBasic},
		{"detailed", monitor.LevelDetailed},
		{"full", monitor.LevelFull},
		{"", monitor.LevelBasic},
		{"unknown", monitor.LevelBasic},
	}
	for _, c := range cases {
		got := parseMonitorLevel(c.in)
		if got != c.want {
			t.Errorf("parseMonitorLevel(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// ── resolveMonitorInterval ───────────────────────────────────────────────────

func TestResolveMonitorInterval(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want time.Duration
	}{
		{5 * time.Second, 5 * time.Second},
		{time.Minute, time.Minute},
		{0, 10 * time.Second},
		{-1 * time.Second, 10 * time.Second},
	}
	for _, c := range cases {
		got := resolveMonitorInterval(c.in)
		if got != c.want {
			t.Errorf("resolveMonitorInterval(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

// ── isClosedPipeError ────────────────────────────────────────────────────────

func TestIsClosedPipeError(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"broken pipe", true},
		{"file already closed", true},
		{"use of closed network connection", true},
		{"some other error", false},
		{"", false},
	}
	for _, c := range cases {
		var err error
		if c.msg != "" {
			err = &testError{msg: c.msg}
		}
		got := isClosedPipeError(err)
		if got != c.want {
			t.Errorf("isClosedPipeError(%q) = %v, want %v", c.msg, got, c.want)
		}
	}
	// nil error
	if isClosedPipeError(nil) {
		t.Error("isClosedPipeError(nil) should be false")
	}
}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

// ── prepareCredentials ───────────────────────────────────────────────────────

func TestPrepareCredentials_MergesOverrides(t *testing.T) {
	cfg := &config.Config{}
	def := config.ToolDef{}
	overrides := []string{"MY_KEY=myval"}

	finalCreds, sandboxCreds := prepareCredentials(cfg, def, overrides)

	// The override should appear in both slices.
	foundFinal := false
	for _, c := range finalCreds {
		if c.Key == "MY_KEY" && c.Value == "myval" && c.Source == "cli" {
			foundFinal = true
			break
		}
	}
	if !foundFinal {
		t.Error("expected MY_KEY in finalCreds")
	}

	foundSandbox := false
	for _, c := range sandboxCreds {
		if c.Key == "MY_KEY" && c.Value == "myval" {
			foundSandbox = true
			break
		}
	}
	if !foundSandbox {
		t.Error("expected MY_KEY in sandboxCreds")
	}
}

// ── createContext ─────────────────────────────────────────────────────────────

func TestCreateContext_NoTimeout(t *testing.T) {
	cfg := &config.Config{}
	ctx, cancel := createContext(cfg)
	defer cancel()

	if _, ok := ctx.Deadline(); ok {
		t.Error("context should have no deadline when timeout is 0")
	}
}

func TestCreateContext_WithTimeout(t *testing.T) {
	cfg := &config.Config{
		Resources: config.ResourceConfig{Timeout: 5 * time.Second},
	}
	ctx, cancel := createContext(cfg)
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("context should have a deadline")
	}
	remaining := time.Until(deadline)
	if remaining < 4*time.Second || remaining > 6*time.Second {
		t.Errorf("deadline should be ~5s from now, got %v", remaining)
	}
}
