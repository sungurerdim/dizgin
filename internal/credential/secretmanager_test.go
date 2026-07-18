// SPDX-License-Identifier: MIT

package credential

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// --- DotenvProvider ---

func TestDotenvProvider_Get_ReadsEnvFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".env"), "API_KEY=from-env\n")

	p := NewDotenvProvider(dir)
	got, err := p.Get("API_KEY")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "from-env" {
		t.Errorf("got %q, want %q", got, "from-env")
	}
}

func TestDotenvProvider_Get_LocalOverridesBase(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".env"), "API_KEY=base\n")
	writeFile(t, filepath.Join(dir, ".env.local"), "API_KEY=local\n")

	p := NewDotenvProvider(dir)
	got, err := p.Get("API_KEY")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "local" {
		t.Errorf(".env.local must override .env: got %q, want %q", got, "local")
	}
}

func TestDotenvProvider_Get_MissingKey(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".env"), "OTHER_KEY=x\n")

	p := NewDotenvProvider(dir)
	got, err := p.Get("API_KEY")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "" {
		t.Errorf("missing key: got %q, want empty", got)
	}
}

func TestDotenvProvider_Get_NoFilesPresent(t *testing.T) {
	p := NewDotenvProvider(t.TempDir())
	got, err := p.Get("ANYTHING")
	if err != nil {
		t.Fatalf("Get on empty dir: unexpected error %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestDotenvProvider_Name(t *testing.T) {
	if got := (&DotenvProvider{}).Name(); got != "dotenv" {
		t.Errorf("Name() = %q, want %q", got, "dotenv")
	}
}

func TestParseDotenvFile_QuotesCommentsAndBlankLines(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, ".env")
	writeFile(t, f, "\n# a comment\nDOUBLE=\"double quoted\"\nSINGLE='single quoted'\nBARE=bareword\nNOEQUALS\n")

	vals, err := parseDotenvFile(f)
	if err != nil {
		t.Fatalf("parseDotenvFile: %v", err)
	}
	want := map[string]string{
		"DOUBLE": "double quoted",
		"SINGLE": "single quoted",
		"BARE":   "bareword",
	}
	for k, v := range want {
		if vals[k] != v {
			t.Errorf("%s: got %q, want %q", k, vals[k], v)
		}
	}
	if _, ok := vals["NOEQUALS"]; ok {
		t.Error("line without '=' must not produce a key")
	}
}

func TestLoadDotenvFile_MissingFileReturnsEmptyNotError(t *testing.T) {
	vals, err := loadDotenvFile(filepath.Join(t.TempDir(), "does-not-exist.env"))
	if err != nil {
		t.Fatalf("missing file must not error, got %v", err)
	}
	if len(vals) != 0 {
		t.Errorf("got %v, want empty map", vals)
	}
}

// --- VaultProvider ---

func TestNewVaultProvider_DefaultsMountPath(t *testing.T) {
	p := NewVaultProvider("", "app/config")
	if p.mountPath != "secret" {
		t.Errorf("default mountPath: got %q, want %q", p.mountPath, "secret")
	}
	if p.secretPath != "app/config" {
		t.Errorf("secretPath: got %q, want %q", p.secretPath, "app/config")
	}
}

func TestVaultProvider_Name(t *testing.T) {
	if got := (&VaultProvider{}).Name(); got != "vault" {
		t.Errorf("Name() = %q, want %q", got, "vault")
	}
}

func TestVaultProvider_Get_SkipsSilentlyWhenBinaryMissing(t *testing.T) {
	// Point PATH at an empty directory so exec.LookPath("vault") always
	// fails, regardless of what's actually installed on the host running
	// this test.
	t.Setenv("PATH", t.TempDir())
	t.Setenv("VAULT_ADDR", "https://vault.example.com")

	p := NewVaultProvider("secret", "app/config")
	got, err := p.Get("SOME_KEY")
	if err != nil {
		t.Fatalf("vault not installed must not error, got %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty (vault not installed)", got)
	}
}

func TestVaultProvider_Get_SkipsSilentlyWhenAddrUnset(t *testing.T) {
	// A fake, always-on-PATH "vault" binary that would fail loudly if
	// invoked — the test only passes if Get() short-circuits on the
	// missing VAULT_ADDR check before ever exec'ing it.
	binDir := t.TempDir()
	fakeVault := filepath.Join(binDir, "vault")
	script := "#!/bin/sh\necho 'should never run' >&2\nexit 1\n"
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary PATH shim is POSIX shell only")
	}
	writeFile(t, fakeVault, script)
	if err := os.Chmod(fakeVault, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("VAULT_ADDR", "")

	p := NewVaultProvider("secret", "app/config")
	got, err := p.Get("SOME_KEY")
	if err != nil {
		t.Fatalf("unset VAULT_ADDR must not error, got %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty (VAULT_ADDR unset)", got)
	}
}

// --- DiscoverFromProviders ---

type fakeProvider struct {
	name string
	val  string
	err  error
}

func (f *fakeProvider) Name() string { return f.name }
func (f *fakeProvider) Get(key string) (string, error) {
	return f.val, f.err
}

func TestDiscoverFromProviders_FirstNonEmptyWins(t *testing.T) {
	t.Setenv("MY_KEY", "") // ensure not already set in the environment

	providers := []SecretProvider{
		&fakeProvider{name: "first", val: ""},
		&fakeProvider{name: "second", val: "second-value"},
		&fakeProvider{name: "third", val: "third-value"},
	}
	found := DiscoverFromProviders(providers, []string{"MY_KEY"})

	if len(found) != 1 {
		t.Fatalf("got %d credentials, want 1", len(found))
	}
	if found[0].Source != "second" {
		t.Errorf("source: got %q, want %q (first provider with a non-empty value)", found[0].Source, "second")
	}
	if found[0].Value != "second-value" {
		t.Errorf("value: got %q, want %q", found[0].Value, "second-value")
	}
}

func TestDiscoverFromProviders_SkipsKeyAlreadyInEnv(t *testing.T) {
	t.Setenv("ALREADY_SET_KEY", "existing-value")

	providers := []SecretProvider{
		&fakeProvider{name: "only", val: "would-be-found"},
	}
	found := DiscoverFromProviders(providers, []string{"ALREADY_SET_KEY"})

	if len(found) != 0 {
		t.Errorf("key already in env must be skipped, got %+v", found)
	}
}

func TestDiscoverFromProviders_ProviderErrorFallsThroughToNext(t *testing.T) {
	t.Setenv("MY_KEY", "")

	providers := []SecretProvider{
		&fakeProvider{name: "broken", err: fmt.Errorf("boom")},
		&fakeProvider{name: "backup", val: "backup-value"},
	}
	found := DiscoverFromProviders(providers, []string{"MY_KEY"})

	if len(found) != 1 {
		t.Fatalf("got %d credentials, want 1", len(found))
	}
	if found[0].Source != "backup" {
		t.Errorf("source: got %q, want %q", found[0].Source, "backup")
	}
}

func TestDiscoverFromProviders_NoProviderHasIt(t *testing.T) {
	t.Setenv("MY_KEY", "")

	providers := []SecretProvider{
		&fakeProvider{name: "a", val: ""},
		&fakeProvider{name: "b", val: ""},
	}
	found := DiscoverFromProviders(providers, []string{"MY_KEY"})
	if len(found) != 0 {
		t.Errorf("no provider found a value: got %+v, want empty", found)
	}
}

// --- helpers ---

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
