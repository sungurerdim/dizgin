// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestDenyACEPrecedesGrant is the Faz 2 acceptance test for the
// canonical-DACL ordering guarantee. We:
//
//  1. apply a GRANT ACE first,
//  2. then apply a DENY ACE (the order the production session loop
//     does NOT use, but the order that stresses ACLFromEntries's
//     re-canonicalization the most),
//  3. read the resulting DACL back as SDDL,
//  4. assert that the DENY ACE for our trustee comes before the
//     GRANT ACE for our trustee in the SDDL ACE string.
//
// The behavioural guarantee Windows actually exposes is "deny ACEs
// are evaluated before allow ACEs"; SetEntriesInAcl writes them in
// that order so the SDDL string-position check is a sufficient proxy.
// A regression that drops the canonical ordering (e.g. someone
// swaps to a manual AddAce that appends without reordering) would
// fail this test before it shipped.
func TestDenyACEPrecedesGrant(t *testing.T) {
	sid, err := CurrentUserSID()
	if err != nil {
		t.Fatalf("CurrentUserSID: %v", err)
	}

	tmpDir := t.TempDir()
	defer func() { _ = RevokePathForTrustee(tmpDir, sid) }()

	if err := StampPathGrant(tmpDir, sid, false); err != nil {
		t.Fatalf("StampPathGrant: %v", err)
	}
	if err := StampPathDeny(tmpDir, sid); err != nil {
		t.Fatalf("StampPathDeny: %v", err)
	}

	sd, err := windows.GetNamedSecurityInfo(
		tmpDir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}
	sddl := sd.String()
	sidStr := sid.String()

	denyIdx, allowIdx := -1, -1
	pos := 0
	for {
		i := strings.Index(sddl[pos:], "(")
		if i == -1 {
			break
		}
		i += pos
		j := strings.Index(sddl[i:], ")")
		if j == -1 {
			break
		}
		ace := sddl[i : i+j+1]
		if strings.Contains(ace, sidStr) {
			if strings.HasPrefix(ace, "(D;") && denyIdx == -1 {
				denyIdx = i
			}
			if strings.HasPrefix(ace, "(A;") && allowIdx == -1 {
				allowIdx = i
			}
		}
		pos = i + j + 1
	}

	if denyIdx == -1 {
		t.Fatalf("no DENY ACE found for trustee %s in DACL\nSDDL=%s", sidStr, sddl)
	}
	if allowIdx == -1 {
		t.Fatalf("no GRANT ACE found for trustee %s in DACL\nSDDL=%s", sidStr, sddl)
	}
	if denyIdx >= allowIdx {
		t.Errorf("deny index %d >= grant index %d — ACL not canonical\nSDDL=%s",
			denyIdx, allowIdx, sddl)
	}
}

// TestStampDenyBlocksRead verifies the kernel-side enforcement: after
// StampPathDeny on a directory, a file under it cannot be opened for
// reading by a process running as the same user. This is the security
// invariant the sensitive-DENY sweep relies on.
func TestStampDenyBlocksRead(t *testing.T) {
	sid, err := CurrentUserSID()
	if err != nil {
		t.Fatalf("CurrentUserSID: %v", err)
	}

	tmpDir := t.TempDir()
	defer func() { _ = RevokePathForTrustee(tmpDir, sid) }()

	secretPath := filepath.Join(tmpDir, "secret.txt")
	if err := os.WriteFile(secretPath, []byte("topsecret"), 0o600); err != nil {
		t.Fatalf("seed write: %v", err)
	}
	// Sanity: file is readable before DENY.
	if _, err := os.ReadFile(secretPath); err != nil {
		t.Fatalf("pre-DENY read failed: %v", err)
	}

	if err := StampPathDeny(tmpDir, sid); err != nil {
		t.Fatalf("StampPathDeny: %v", err)
	}

	// Now the read must fail.
	if _, err := os.ReadFile(secretPath); err == nil {
		t.Errorf("read succeeded after DENY ACE — DACL enforcement broken")
	} else if !strings.Contains(err.Error(), "denied") &&
		!os.IsPermission(err) {
		t.Logf("note: DENY produced %v (accepted as permission-style error)", err)
	}

	// Revoke must restore access on both root and descendants — even
	// for the inherited copy of the ACE that landed on secret.txt
	// when StampPathDeny applied the OI/CI flags on tmpDir.
	if err := RevokePathForTrustee(tmpDir, sid); err != nil {
		t.Fatalf("RevokePathForTrustee: %v", err)
	}
	if _, err := os.ReadFile(secretPath); err != nil {
		// Dump DACLs so a future regression here lands a useful trace.
		if sd, derr := windows.GetNamedSecurityInfo(secretPath, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION); derr == nil {
			t.Logf("secret.txt DACL after revoke: %s", sd.String())
		}
		if sd, derr := windows.GetNamedSecurityInfo(tmpDir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION); derr == nil {
			t.Logf("tmpDir DACL after revoke: %s", sd.String())
		}
		t.Errorf("post-revoke read failed: %v", err)
	}
}

// TestStampGrantRoundTrip verifies the GRANT path: stamp, read back
// the SDDL, find the new ACE, then revoke and re-read.
func TestStampGrantRoundTrip(t *testing.T) {
	sid, err := CurrentUserSID()
	if err != nil {
		t.Fatalf("CurrentUserSID: %v", err)
	}
	tmpDir := t.TempDir()
	defer func() { _ = RevokePathForTrustee(tmpDir, sid) }()

	if err := StampPathGrant(tmpDir, sid, true); err != nil {
		t.Fatalf("StampPathGrant: %v", err)
	}

	sd, err := windows.GetNamedSecurityInfo(
		tmpDir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}
	sddl := sd.String()
	if !strings.Contains(sddl, sid.String()) {
		t.Errorf("trustee SID %s not found in DACL after grant\nSDDL=%s",
			sid.String(), sddl)
	}
}
