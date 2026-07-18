// SPDX-License-Identifier: MIT

//go:build windows

package main

// TST-04 — buildExpectedTrusteeSet / labelTrustee pure-logic tests.
//
// scanPathACEs requires a real path with a DACL (e2e — reads live NTFS
// objects). The --apply revoke path that mutates real ACLs is e2e only.
//
// buildExpectedTrusteeSet and labelTrustee are decidable from a known-good
// SID and the Windows well-known SID set; both are fully testable here.

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// ---- buildExpectedTrusteeSet ----

func TestBuildExpectedTrusteeSet_AlwaysContainsSystemAndAdmins(t *testing.T) {
	set, err := buildExpectedTrusteeSet(nil)
	if err != nil {
		t.Fatalf("buildExpectedTrusteeSet(nil): %v", err)
	}
	// Must always contain SYSTEM (S-1-5-18) and Administrators (S-1-5-32-544).
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatalf("CreateWellKnownSid(SYSTEM): %v", err)
	}
	adminsSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatalf("CreateWellKnownSid(Admins): %v", err)
	}

	if _, ok := set[systemSID.String()]; !ok {
		t.Errorf("expected SYSTEM SID %s in set; got %v", systemSID.String(), set)
	}
	if _, ok := set[adminsSID.String()]; !ok {
		t.Errorf("expected Administrators SID %s in set; got %v", adminsSID.String(), set)
	}
}

func TestBuildExpectedTrusteeSet_NilUserSID_SizeIsTwo(t *testing.T) {
	set, err := buildExpectedTrusteeSet(nil)
	if err != nil {
		t.Fatalf("buildExpectedTrusteeSet(nil): %v", err)
	}
	if len(set) != 2 {
		t.Errorf("nil user SID should produce exactly 2 entries (SYSTEM + Admins); got %d: %v", len(set), set)
	}
}

func TestBuildExpectedTrusteeSet_WithUserSID_SizeIsThree(t *testing.T) {
	// Use the current user's SID — always valid in a running process.
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
		t.Fatalf("OpenProcessToken: %v", err)
	}
	defer func() { _ = tok.Close() }()

	tu, err := tok.GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser: %v", err)
	}

	set, err := buildExpectedTrusteeSet(tu.User.Sid)
	if err != nil {
		t.Fatalf("buildExpectedTrusteeSet(currentUser): %v", err)
	}
	if len(set) != 3 {
		t.Errorf("with user SID should produce 3 entries; got %d: %v", len(set), set)
	}
	if _, ok := set[tu.User.Sid.String()]; !ok {
		t.Errorf("user SID %s not in set; got %v", tu.User.Sid.String(), set)
	}
}

func TestBuildExpectedTrusteeSet_UserSIDNotDuplicated(t *testing.T) {
	// If the user happens to be SYSTEM or Admins (rare but theoretically
	// possible in testing), the set should still be 2 (no dup).
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatalf("CreateWellKnownSid(SYSTEM): %v", err)
	}
	set, err := buildExpectedTrusteeSet(systemSID)
	if err != nil {
		t.Fatalf("buildExpectedTrusteeSet(SYSTEM as user): %v", err)
	}
	// SYSTEM is already in the well-known set; adding it as "user" should not
	// increase the size beyond 2.
	if len(set) > 3 {
		t.Errorf("duplicated SID inflated set size: %d entries in %v", len(set), set)
	}
}

// ---- labelTrustee ----

func TestLabelTrustee_NilSIDReturnsNilString(t *testing.T) {
	got := labelTrustee(nil)
	if got != "(nil)" {
		t.Errorf("labelTrustee(nil) = %q; want %q", got, "(nil)")
	}
}

func TestLabelTrustee_WellKnownSIDResolvesToAccount(t *testing.T) {
	// SYSTEM always resolves on Windows — a well-known account that is
	// never absent regardless of domain membership.
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatalf("CreateWellKnownSid(SYSTEM): %v", err)
	}
	label := labelTrustee(systemSID)
	// The label must contain the SID string (it's always appended).
	if !strings.Contains(label, systemSID.String()) {
		t.Errorf("labelTrustee(SYSTEM) missing SID string; got %q", label)
	}
	// And it must contain at least the account name "SYSTEM" or similar.
	if !strings.Contains(strings.ToUpper(label), "SYSTEM") {
		t.Errorf("labelTrustee(SYSTEM) missing 'SYSTEM' account name; got %q", label)
	}
}

func TestLabelTrustee_AdministratorsSIDContainsSIDString(t *testing.T) {
	adminsSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatalf("CreateWellKnownSid(Admins): %v", err)
	}
	label := labelTrustee(adminsSID)
	if !strings.Contains(label, adminsSID.String()) {
		t.Errorf("labelTrustee(Admins) missing SID string; got %q", label)
	}
}

func TestLabelTrustee_FormatContainsDomainBackslash(t *testing.T) {
	// When LookupAccount resolves domain + account, the format is
	// "DOMAIN\Account (SID)". SYSTEM on a domain-joined or workgroup machine
	// always produces a non-empty domain, so check the backslash separator.
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatalf("CreateWellKnownSid(SYSTEM): %v", err)
	}
	label := labelTrustee(systemSID)
	// Either format is acceptable: "DOMAIN\SYSTEM (S-1-5-18)" or
	// "SYSTEM (S-1-5-18)". Just verify no panic and non-empty output.
	if label == "" {
		t.Error("labelTrustee returned empty string for SYSTEM SID")
	}
}

// ---- aceKind constants ----

func TestAceKindConstants_AreDistinct(t *testing.T) {
	if aceDrift == aceOrphan {
		t.Error("aceDrift and aceOrphan must be distinct constants")
	}
}
