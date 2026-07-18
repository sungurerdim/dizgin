// SPDX-License-Identifier: MIT

//go:build schemagen

package main

import (
	"testing"
)

func TestYamlKey_KnownField(t *testing.T) {
	// "Version" is a field on config.Config with yaml:"version".
	got := yamlKey("Version")
	if got != "version" {
		t.Errorf("yamlKey(\"Version\") = %q, want \"version\"", got)
	}
}

func TestYamlKey_UnknownField(t *testing.T) {
	got := yamlKey("NoSuchField")
	if got != "nosuchfield" {
		t.Errorf("yamlKey(\"NoSuchField\") = %q, want \"nosuchfield\"", got)
	}
}

func TestYamlTagFor_ConfigField(t *testing.T) {
	cases := []struct {
		field string
		want  string
	}{
		{"Version", "version"},
		{"Tool", "tool"},
		{"Workdir", "workdir"},
		{"Network", "network"},
		{"Resources", "resources"},
		{"Audit", "audit"},
		{"Security", "security"},
		{"Privileges", "privileges"},
		{"Credential", "credential"},
		{"Filesystem", "filesystem"},
		{"Monitor", "monitor"},
	}
	for _, c := range cases {
		got := yamlTagFor(c.field)
		if got != c.want {
			t.Errorf("yamlTagFor(%q) = %q, want %q", c.field, got, c.want)
		}
	}
}

func TestYamlTagFor_FilesystemField(t *testing.T) {
	got := yamlTagFor("TmpSize")
	if got != "tmp_size" {
		t.Errorf("yamlTagFor(\"TmpSize\") = %q, want \"tmp_size\"", got)
	}
}

func TestYamlTagFor_NetworkField(t *testing.T) {
	got := yamlTagFor("Policy")
	if got != "policy" {
		t.Errorf("yamlTagFor(\"Policy\") = %q, want \"policy\"", got)
	}
}

func TestYamlTagFor_ResourceField(t *testing.T) {
	got := yamlTagFor("MemoryMB")
	if got != "memory_mb" {
		t.Errorf("yamlTagFor(\"MemoryMB\") = %q, want \"memory_mb\"", got)
	}
}

func TestYamlTagFor_UnknownField(t *testing.T) {
	got := yamlTagFor("CompletelyFake")
	if got != "" {
		t.Errorf("yamlTagFor(\"CompletelyFake\") = %q, want \"\"", got)
	}
}

func TestYamlTagFor_ToolDefField(t *testing.T) {
	got := yamlTagFor("ConfigDirs")
	if got != "config_dirs" {
		t.Errorf("yamlTagFor(\"ConfigDirs\") = %q, want \"config_dirs\"", got)
	}
}

func TestYamlTagFor_AuditField(t *testing.T) {
	got := yamlTagFor("Enabled")
	if got != "enabled" {
		t.Errorf("yamlTagFor(\"Enabled\") = %q, want \"enabled\"", got)
	}
}

func TestYamlTagFor_CredentialField(t *testing.T) {
	got := yamlTagFor("SSHAgent")
	if got != "ssh_agent" {
		t.Errorf("yamlTagFor(\"SSHAgent\") = %q, want \"ssh_agent\"", got)
	}
}
