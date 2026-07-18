// SPDX-License-Identifier: MIT

package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sungurerdim/dizgin/internal/brand"
)

func TestMountAuditDir_UnderHome(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir) // os.UserHomeDir() reads this on Windows

	got, err := mountAuditDir()
	if err != nil {
		t.Fatalf("mountAuditDir: %v", err)
	}
	want := filepath.Join(dir, brand.DotDir, "audit")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestLogMountDecision_WritesJSONLRecord(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	LogMountDecision("sess-abc", MountDecision{
		Category: "declared_ro",
		Host:     "/usr/local/bin",
		ReadOnly: true,
		Granted:  true,
	})

	path := filepath.Join(dir, brand.DotDir, "audit", "sess-abc.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}

	var got MountDecision
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}
	if got.Session != "sess-abc" {
		t.Errorf("session: got %q, want %q", got.Session, "sess-abc")
	}
	if got.Category != "declared_ro" {
		t.Errorf("category: got %q, want %q", got.Category, "declared_ro")
	}
	if got.Host != "/usr/local/bin" {
		t.Errorf("host: got %q, want %q", got.Host, "/usr/local/bin")
	}
	if !got.ReadOnly || !got.Granted {
		t.Errorf("ReadOnly/Granted: got %v/%v, want true/true", got.ReadOnly, got.Granted)
	}
	if got.Time == "" {
		t.Error("Time should be stamped by LogMountDecision")
	}
}

func TestLogMountDecision_AppendsMultipleLines(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	LogMountDecision("sess-multi", MountDecision{Category: "workdir", Host: "/proj", Granted: true})
	LogMountDecision("sess-multi", MountDecision{Category: "declared_rw", Host: "/cache", Granted: true})

	path := filepath.Join(dir, brand.DotDir, "audit", "sess-multi.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %v", len(lines), lines)
	}
}

func TestLogMountDecision_EmptySessionIDIsNoOp(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	LogMountDecision("", MountDecision{Category: "workdir", Host: "/proj"})

	entries, err := os.ReadDir(filepath.Join(dir, brand.DotDir, "audit"))
	if err == nil && len(entries) != 0 {
		t.Errorf("expected no audit file written for empty session ID, found %v", entries)
	}
}

func TestLogMountDecision_DisabledViaEnvVar(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv(brand.Env("AUDIT_MOUNTS"), "0")

	LogMountDecision("sess-disabled", MountDecision{Category: "workdir", Host: "/proj"})

	path := filepath.Join(dir, brand.DotDir, "audit", "sess-disabled.jsonl")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected no file written when DIZGIN_AUDIT_MOUNTS=0, stat err=%v", err)
	}
}
