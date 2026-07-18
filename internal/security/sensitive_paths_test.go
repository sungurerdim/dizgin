// SPDX-License-Identifier: MIT

package security

import (
	"path/filepath"
	"strings"
	"testing"
)

// These tests exercise the platform-neutral matcher against whatever
// sensitiveRelativePaths / sensitiveFoldCase the current OS supplies, so
// the separator-boundary and case-folding contracts are verified on every
// platform the suite runs on — not just Windows.

func TestIsSensitiveDenyAt_SeparatorBoundary(t *testing.T) {
	home := filepath.Join(string(filepath.Separator)+"home", "dev")

	// ~/.ssh is in every OS SSOT — use it as the anchor for boundary tests.
	sshDir := filepath.Join(home, ".ssh")

	if !IsSensitiveDenyAt(sshDir, home) {
		t.Fatalf("expected %q to be sensitive", sshDir)
	}
	// A descendant is sensitive.
	if got := IsSensitiveDenyAt(filepath.Join(sshDir, "id_ed25519"), home); !got {
		t.Errorf("descendant of .ssh should be sensitive")
	}
	// A sibling that merely shares the prefix string is NOT sensitive.
	sibling := filepath.Join(home, ".sshd_config")
	if IsSensitiveDenyAt(sibling, home) {
		t.Errorf("%q must not match .ssh (separator-boundary bug)", sibling)
	}
	// Empty inputs are never sensitive.
	if IsSensitiveDenyAt("", home) || IsSensitiveDenyAt(sshDir, "") {
		t.Errorf("empty host or home must not match")
	}
}

func TestIsSensitiveDenyAt_CaseFolding(t *testing.T) {
	home := filepath.Join(string(filepath.Separator)+"home", "dev")
	upper := filepath.Join(home, ".SSH")

	got := IsSensitiveDenyAt(upper, home)
	if sensitiveFoldCase && !got {
		t.Errorf("case-insensitive OS: %q should match .ssh", upper)
	}
	if !sensitiveFoldCase && got {
		t.Errorf("case-sensitive OS: %q must not match .ssh", upper)
	}
}

func TestSensitiveDenyPaths_EmptyHome(t *testing.T) {
	if got := SensitiveDenyPaths(""); got != nil {
		t.Errorf("SensitiveDenyPaths(\"\") = %v, want nil", got)
	}
}

func TestSensitiveDenyPaths_ExpandsAllEntries(t *testing.T) {
	home := filepath.Join(string(filepath.Separator)+"home", "dev")
	got := SensitiveDenyPaths(home)
	if len(got) != len(SensitiveRelativePaths()) {
		t.Fatalf("expanded %d paths, want %d", len(got), len(SensitiveRelativePaths()))
	}
	for _, p := range got {
		if !strings.HasPrefix(p, home+string(filepath.Separator)) {
			t.Errorf("expanded path %q not rooted at home %q", p, home)
		}
	}
}

// The SSOT must always cover the universal credential surfaces on every OS.
func TestSSOT_CoversCoreCredentials(t *testing.T) {
	rels := SensitiveRelativePaths()
	joined := strings.ToLower(strings.Join(rels, "\x00"))
	for _, must := range []string{".ssh", "gnupg", "aws", "gcloud", "azure", "kube"} {
		if !strings.Contains(joined, must) {
			t.Errorf("SSOT missing a %q credential surface; have %v", must, rels)
		}
	}
}
