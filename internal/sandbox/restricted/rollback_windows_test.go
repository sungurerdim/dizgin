// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRevokeStampsParallel_RollsBackAll exercises the mechanism the
// fail-closed path in backend.Create relies on: when DENY application
// aborts partway, revokeStampsParallel must lift the DENY from EVERY
// already-stamped path so the user is never left locked out of their own
// credential dirs. Here we stamp several dirs, confirm each blocks reads,
// then revoke the whole set in one parallel sweep and confirm access is
// restored everywhere.
func TestRevokeStampsParallel_RollsBackAll(t *testing.T) {
	sid, err := CurrentUserSID()
	if err != nil {
		t.Fatalf("CurrentUserSID: %v", err)
	}

	const n = 3
	dirs := make([]string, 0, n)
	files := make([]string, 0, n)
	for i := 0; i < n; i++ {
		d := t.TempDir()
		f := filepath.Join(d, "secret.txt")
		if err := os.WriteFile(f, []byte("topsecret"), 0o600); err != nil {
			t.Fatalf("seed write: %v", err)
		}
		dirs = append(dirs, d)
		files = append(files, f)
	}
	// Always clean up even if an assertion fails mid-test.
	defer func() {
		for _, d := range dirs {
			_ = RevokePathForTrustee(d, sid)
		}
	}()

	for i, d := range dirs {
		if err := StampPathDeny(d, sid); err != nil {
			t.Fatalf("StampPathDeny(%s): %v", d, err)
		}
		if _, err := os.ReadFile(files[i]); err == nil {
			t.Errorf("read succeeded after DENY on %s — enforcement broken", d)
		}
	}

	// The rollback sweep used by the fail-closed Create path.
	revokeStampsParallel(dirs, sid)

	for _, f := range files {
		if _, err := os.ReadFile(f); err != nil {
			t.Errorf("post-rollback read failed for %s: %v", f, err)
		}
	}
}

// TestLearnRoundTrip_SaveLoadExempt ties the --learn persistence to the
// next-run enforcement decision: a path the user authorised (RO) is
// written to disk, reloaded, and then exempted by isPathExempt — the
// exact check buildSensitiveDenyJobs uses to skip re-DENYing a path the
// user opted into. A path NOT in the profile stays non-exempt.
func TestLearnRoundTrip_SaveLoadExempt(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)

	const tool = "ztestround"
	authorized := filepath.Join(home, ".config", "ztestround", "settings.json")
	other := filepath.Join(home, ".ssh", "id_rsa")

	if err := SavePermissionProfile(&PermissionProfile{
		ToolName:  tool,
		Overrides: Overrides{RO: []string{authorized}},
	}); err != nil {
		t.Fatalf("SavePermissionProfile: %v", err)
	}

	loaded, err := LoadPermissionProfile(tool)
	if err != nil {
		t.Fatalf("LoadPermissionProfile: %v", err)
	}
	ov := loaded.Overrides.ToSandboxOverrides()
	if ov == nil {
		t.Fatal("ToSandboxOverrides returned nil for a profile with an RO entry")
	}

	if !isPathExempt(canonical(authorized), ov) {
		t.Errorf("authorized RO path %q should be exempt after round-trip", authorized)
	}
	if isPathExempt(canonical(other), ov) {
		t.Errorf("unlisted path %q must NOT be exempt", other)
	}
}

// canonical mirrors the lowercase+clean form stored/compared internally
// so the exemption check matches regardless of input casing.
func canonical(p string) string {
	return canonicalisePaths([]string{p})[0]
}
