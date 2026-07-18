// SPDX-License-Identifier: MIT

package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestConfigDirList_Unmarshal_MixedShapes(t *testing.T) {
	src := `
- "~/.claude.json"
- path: "~/.claude"
  mode: rw
  source: profile
- path: "/opt/readonly-dep"
  mode: ro
  source: manual
`
	var list ConfigDirList
	if err := yaml.Unmarshal([]byte(src), &list); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(list))
	}
	// Bare string promoted to rw/profile.
	if list[0].Path != "~/.claude.json" || list[0].Mode != "rw" || list[0].Source != "profile" {
		t.Errorf("entry[0] = %+v", list[0])
	}
	// Structured rw.
	if list[1].Path != "~/.claude" || list[1].Mode != "rw" {
		t.Errorf("entry[1] = %+v", list[1])
	}
	// Structured ro with explicit source.
	if list[2].Path != "/opt/readonly-dep" || list[2].Mode != "ro" || list[2].Source != "manual" {
		t.Errorf("entry[2] = %+v", list[2])
	}
	if !list[2].ReadOnly() {
		t.Error("ro entry should ReadOnly()==true")
	}
	if list[0].ReadOnly() {
		t.Error("rw entry should ReadOnly()==false")
	}
}

func TestConfigDirList_Unmarshal_RejectsMissingPath(t *testing.T) {
	src := `
- mode: rw
`
	var list ConfigDirList
	err := yaml.Unmarshal([]byte(src), &list)
	if err == nil {
		t.Fatal("expected error on missing path")
	}
	if !strings.Contains(err.Error(), "missing path") {
		t.Errorf("error should mention missing path: %v", err)
	}
}

func TestConfigDirList_Paths(t *testing.T) {
	list := ConfigDirList{
		{Path: "a", Mode: "rw"},
		{Path: "b", Mode: "ro"},
	}
	paths := list.Paths()
	if len(paths) != 2 || paths[0] != "a" || paths[1] != "b" {
		t.Errorf("Paths() = %v", paths)
	}
}

func TestToolDef_ExpandedConfigMounts_Fallback(t *testing.T) {
	// Legacy path: only ConfigDirs is set. ExpandedConfigMounts should
	// promote to entries with Mode=rw, Source=profile.
	t.Setenv("HOME", "/tmp/does-not-matter")
	td := ToolDef{
		ConfigDirs: []string{"/absolute/path"},
	}
	got := td.ExpandedConfigMounts()
	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got))
	}
	if got[0].Mode != "rw" || got[0].Source != "profile" || got[0].Path != "/absolute/path" {
		t.Errorf("entry = %+v", got[0])
	}
}

func TestToolDef_ExpandedConfigMounts_PrefersStructured(t *testing.T) {
	td := ToolDef{
		ConfigDirs: []string{"/legacy"},
		ConfigDirMounts: []ConfigDirEntry{
			{Path: "/structured", Mode: "ro", Source: "manual"},
		},
	}
	got := td.ExpandedConfigMounts()
	if len(got) != 1 || got[0].Path != "/structured" || !got[0].ReadOnly() {
		t.Errorf("expected structured RO entry, got %+v", got)
	}
}
