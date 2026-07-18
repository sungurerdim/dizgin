// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/sandbox"
)

// withTempHome redirects USERPROFILE + HOME to a fresh temp dir for
// the duration of the test so permissionsDir() lands on an isolated
// tree. Returns the home path. t.Cleanup restores the original env.
func withTempHome(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	originalUP := os.Getenv("USERPROFILE")
	originalHome := os.Getenv("HOME")
	t.Setenv("USERPROFILE", tmp)
	t.Setenv("HOME", tmp)
	t.Cleanup(func() {
		_ = os.Setenv("USERPROFILE", originalUP)
		_ = os.Setenv("HOME", originalHome)
	})
	return tmp
}

func TestSavePermissionProfile_Roundtrip(t *testing.T) {
	home := withTempHome(t)
	in := &PermissionProfile{
		ToolName: "claude",
		ToolPath: filepath.Join(home, "bin", "claude.exe"),
		Overrides: Overrides{
			RW: []string{filepath.Join(home, "projects", "myapp")},
			RO: []string{filepath.Join(home, ".aws", "credentials")},
		},
	}
	if err := SavePermissionProfile(in); err != nil {
		t.Fatalf("save: %v", err)
	}
	out, err := LoadPermissionProfile("claude")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if out == nil {
		t.Fatal("load returned nil after save")
		return
	}
	if out.ToolName != "claude" {
		t.Errorf("ToolName: got %q want %q", out.ToolName, "claude")
	}
	if out.Version != permissionsSchemaVersion {
		t.Errorf("Version: got %d want %d", out.Version, permissionsSchemaVersion)
	}
	if out.LearnedAt.IsZero() {
		t.Error("LearnedAt should be auto-stamped on save")
	}
	if len(out.Overrides.RW) != 1 || len(out.Overrides.RO) != 1 {
		t.Fatalf("overrides shape: RW=%d RO=%d", len(out.Overrides.RW), len(out.Overrides.RO))
	}
	// Stored canonical form is lowercased.
	if out.Overrides.RW[0] != strings.ToLower(filepath.Clean(in.Overrides.RW[0])) {
		t.Errorf("RW[0] canonicalisation mismatch: got %q", out.Overrides.RW[0])
	}
}

func TestLoadPermissionProfile_MissingFile(t *testing.T) {
	withTempHome(t)
	got, err := LoadPermissionProfile("nonexistent-tool")
	if err != nil {
		t.Fatalf("missing file should return (nil, nil); got err=%v", err)
	}
	if got != nil {
		t.Errorf("missing file should return nil profile; got %+v", got)
	}
}

func TestLoadPermissionProfile_CorruptYAML(t *testing.T) {
	home := withTempHome(t)
	dir := filepath.Join(home, brand.DotDir, "permissions")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.yaml"),
		[]byte("not: valid: yaml: ::\n  random"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadPermissionProfile("broken"); err == nil {
		t.Error("corrupt YAML should return an error, not (nil, nil)")
	}
}

func TestPermissionPath_NameNormalization(t *testing.T) {
	withTempHome(t)
	a, err := permissionsPath("Claude.EXE")
	if err != nil {
		t.Fatalf("permissionsPath(Claude.EXE): %v", err)
	}
	b, err := permissionsPath("claude")
	if err != nil {
		t.Fatalf("permissionsPath(claude): %v", err)
	}
	if a != b {
		t.Errorf("name normalisation broken: %q vs %q", a, b)
	}
}

func TestPermissionPath_EmptyNameRejected(t *testing.T) {
	withTempHome(t)
	if _, err := permissionsPath(""); err == nil {
		t.Error("empty tool name should be rejected")
	}
}

func TestCanonicalisePaths_EnvExpansion(t *testing.T) {
	home := withTempHome(t)
	in := []string{
		`%USERPROFILE%\.ssh`,
		`~/projects`,
		"  ", // dropped
		"",   // dropped
		`C:\Users\Foo\Bar`,
	}
	got := canonicalisePaths(in)
	if len(got) != 3 {
		t.Fatalf("expected 3 non-empty entries, got %d: %v", len(got), got)
	}
	// All entries should be lowercased + cleaned + env-expanded.
	wantSSH := strings.ToLower(filepath.Clean(filepath.Join(home, ".ssh")))
	if got[0] != wantSSH {
		t.Errorf("USERPROFILE expansion: got %q want %q", got[0], wantSSH)
	}
	wantProj := strings.ToLower(filepath.Clean(filepath.Join(home, "projects")))
	if got[1] != wantProj {
		t.Errorf("tilde expansion: got %q want %q", got[1], wantProj)
	}
	if got[2] != strings.ToLower(`c:\users\foo\bar`) {
		t.Errorf("absolute path canonicalisation: got %q", got[2])
	}
}

func TestExpandTilde(t *testing.T) {
	home := withTempHome(t)
	cases := []struct {
		in, want string
	}{
		{"~", home},
		{"~/foo", filepath.Join(home, "foo")},
		{`~\bar`, filepath.Join(home, "bar")},
		{"/no/tilde", "/no/tilde"},
		{"", ""},
	}
	for _, tc := range cases {
		got := expandTilde(tc.in)
		if got != tc.want {
			t.Errorf("expandTilde(%q) = %q want %q", tc.in, got, tc.want)
		}
	}
}

func TestToSandboxOverrides_EmptyReturnsNil(t *testing.T) {
	o := Overrides{}
	if got := o.ToSandboxOverrides(); got != nil {
		t.Errorf("empty Overrides should project to nil; got %+v", got)
	}
}

func TestToSandboxOverrides_PreservesEntries(t *testing.T) {
	o := Overrides{
		RW:   []string{"c:\\a"},
		RO:   []string{"c:\\b"},
		Deny: []string{"c:\\c"},
	}
	got := o.ToSandboxOverrides()
	if got == nil {
		t.Fatal("non-empty Overrides projected to nil")
		return
	}
	if len(got.RW) != 1 || got.RW[0] != "c:\\a" {
		t.Errorf("RW projection: got %v", got.RW)
	}
	if len(got.RO) != 1 || got.RO[0] != "c:\\b" {
		t.Errorf("RO projection: got %v", got.RO)
	}
	if len(got.Deny) != 1 || got.Deny[0] != "c:\\c" {
		t.Errorf("Deny projection: got %v", got.Deny)
	}
}

func TestFromSandboxOverrides_NilSafe(t *testing.T) {
	got := FromSandboxOverrides(nil)
	if got.RW != nil || got.RO != nil || got.Deny != nil {
		t.Errorf("nil input should yield empty Overrides; got %+v", got)
	}
}

func TestIsPathExempt_NilOverridesNoExempt(t *testing.T) {
	if isPathExempt(`C:\Users\me\.ssh`, nil) {
		t.Error("nil overrides should exempt nothing")
	}
}

func TestIsPathExempt_RWMatches(t *testing.T) {
	ov := &sandbox.PermissionOverrides{
		RW: []string{strings.ToLower(`c:\users\me\.ssh`)},
	}
	if !isPathExempt(`C:\Users\me\.ssh`, ov) {
		t.Error("exact-match RW should exempt")
	}
	if !isPathExempt(`C:\Users\me\.ssh\id_rsa`, ov) {
		t.Error("descendant of RW base should exempt")
	}
	if isPathExempt(`C:\Users\me\.sshd-config`, ov) {
		t.Error("separator-boundary mismatch should NOT exempt")
	}
}

func TestIsPathExempt_RODOes(t *testing.T) {
	ov := &sandbox.PermissionOverrides{
		RO: []string{strings.ToLower(`c:\users\me\.aws\credentials`)},
	}
	if !isPathExempt(`C:\Users\me\.aws\credentials`, ov) {
		t.Error("RO exact match should exempt")
	}
}

func TestSavePermissionProfile_AtomicWriteNoTempLeft(t *testing.T) {
	home := withTempHome(t)
	p := &PermissionProfile{
		ToolName:  "claude",
		Overrides: Overrides{RW: []string{filepath.Join(home, "x")}},
	}
	if err := SavePermissionProfile(p); err != nil {
		t.Fatalf("save: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(home, brand.DotDir, "permissions"))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file left behind after successful save: %s", e.Name())
		}
	}
}

func TestSavePermissionProfile_ConcurrentWritesLastWins(t *testing.T) {
	withTempHome(t)
	const N = 8
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			p := &PermissionProfile{
				ToolName: "claude",
				Overrides: Overrides{
					RW: []string{`c:\concurrent\` + time.Now().Format("150405.000000000")},
				},
			}
			_ = SavePermissionProfile(p)
		}(i)
	}
	wg.Wait()
	// At least one write must have produced a readable file; the file
	// must not be empty or half-written (atomic rename precondition).
	out, err := LoadPermissionProfile("claude")
	if err != nil {
		t.Fatalf("load after concurrent saves: %v", err)
	}
	if out == nil {
		t.Fatal("file missing after N concurrent saves")
		return
	}
	if len(out.Overrides.RW) == 0 {
		t.Error("loaded profile has no RW entries — write was truncated")
	}
}

func TestPermissionProfile_YAMLDoesNotLeakInternalKeys(t *testing.T) {
	home := withTempHome(t)
	p := &PermissionProfile{
		ToolName:  "claude",
		Overrides: Overrides{RW: []string{filepath.Join(home, "x")}},
	}
	if err := SavePermissionProfile(p); err != nil {
		t.Fatalf("save: %v", err)
	}
	path, err := permissionsPath("claude")
	if err != nil {
		t.Fatalf("path: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	body := string(raw)
	for _, k := range []string{"version:", "tool_name:", "learned_at:", "overrides:"} {
		if !strings.Contains(body, k) {
			t.Errorf("YAML missing expected key %q in:\n%s", k, body)
		}
	}
	// Should NOT serialise the unexported helpers under any tag.
	for _, banned := range []string{"sync.Mutex", "RWMutex"} {
		if strings.Contains(body, banned) {
			t.Errorf("YAML leaked internal token %q", banned)
		}
	}
}
