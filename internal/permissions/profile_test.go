// SPDX-License-Identifier: MIT

package permissions

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// writeProfile puts a <tool>.yaml under a temp HOME and returns the tool name.
func writeProfile(t *testing.T, yaml string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, brand.DotDir, "permissions")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "claude.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return "claude"
}

func TestLoad_MissingProfileIsNotAnError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	ov, err := Load("nonesuch")
	if err != nil {
		t.Fatalf("missing profile should be (nil,nil), got err %v", err)
	}
	if ov != nil {
		t.Errorf("missing profile should return nil overrides, got %v", ov)
	}
}

func TestLoad_ExpandsAndCanonicalises(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("MYVAR", "expanded")
	dir := filepath.Join(home, brand.DotDir, "permissions")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	yaml := "version: 1\ntool_name: claude\noverrides:\n" +
		"  rw:\n    - ~/.ssh\n" +
		"  ro:\n    - $MYVAR/config\n" +
		"  deny:\n    - /etc/../etc/secret\n"
	if err := os.WriteFile(filepath.Join(dir, "claude.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	ov, err := Load("claude")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if ov == nil {
		t.Fatal("expected overrides, got nil")
	}
	if len(ov.RW) != 1 || ov.RW[0] != filepath.Join(home, ".ssh") {
		t.Errorf("RW tilde expansion wrong: %v", ov.RW)
	}
	if len(ov.RO) != 1 || ov.RO[0] != "expanded/config" {
		t.Errorf("RO env expansion wrong: %v", ov.RO)
	}
	if len(ov.Deny) != 1 || ov.Deny[0] != "/etc/secret" {
		t.Errorf("Deny not cleaned: %v", ov.Deny)
	}
}

func TestLoad_EmptyOverridesReturnNil(t *testing.T) {
	tool := writeProfile(t, "version: 1\ntool_name: claude\noverrides: {}\n")
	ov, err := Load(tool)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if ov != nil {
		t.Errorf("empty overrides should collapse to nil, got %v", ov)
	}
}

func TestLoad_ToolNameCaseInsensitive(t *testing.T) {
	writeProfile(t, "version: 1\noverrides:\n  ro:\n    - /x\n")
	ov, err := Load("CLAUDE")
	if err != nil || ov == nil {
		t.Fatalf("uppercase tool name should resolve claude.yaml, got ov=%v err=%v", ov, err)
	}
}

func TestLoad_MalformedYAMLIsError(t *testing.T) {
	tool := writeProfile(t, "version: 1\noverrides: [this is not a map\n")
	if _, err := Load(tool); err == nil {
		t.Error("malformed YAML should return an error, not silently succeed")
	}
}
