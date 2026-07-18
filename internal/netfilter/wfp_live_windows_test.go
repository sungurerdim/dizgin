// SPDX-License-Identifier: MIT

//go:build windows

package netfilter

import (
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// isElevated reports whether the test process holds an elevated token.
// WFP filter add requires FWPM_ACTRL_ADD (Administrators), so the live
// round-trip self-skips on a standard token instead of failing.
func isElevated() bool {
	const tokenElevationClass = 20
	type tokenElevation struct{ TokenIsElevated uint32 }
	var elev tokenElevation
	n := uint32(unsafe.Sizeof(elev))
	tok := windows.GetCurrentProcessToken()
	if err := windows.GetTokenInformation(tok, tokenElevationClass, (*byte)(unsafe.Pointer(&elev)), n, &n); err != nil {
		return false
	}
	return elev.TokenIsElevated != 0
}

// TestWFPApplyRevokeRoundTrip exercises the real fwpuclnt.dll path:
// open dynamic engine → app-id → transaction → block(v4/v6) + permit →
// commit, then revoke (close handle → auto-delete). It runs only on an
// elevated host with the Base Filtering Engine service available;
// otherwise it skips, matching the repo's e2e discipline (a feature that
// needs privileges it doesn't have skips rather than fails).
func TestWFPApplyRevokeRoundTrip(t *testing.T) {
	if !isElevated() {
		t.Skip("WFP filter add requires an elevated token (Administrators); skipping live round-trip")
	}
	const sessionID = "test-wfp-roundtrip"
	appPath := `C:\Windows\System32\cmd.exe`

	summary, err := Apply(sessionID, appPath, []string{"203.0.113.10", "2001:db8::1"})
	if err != nil {
		if strings.Contains(err.Error(), "0x5") || strings.Contains(strings.ToLower(err.Error()), "access") {
			t.Skipf("BFE denied add (not enough rights in this elevation context): %v", err)
		}
		t.Fatalf("Apply: %v", err)
	}
	if !strings.Contains(summary, "permit=2") {
		t.Errorf("summary = %q, want permit=2", summary)
	}

	// Double-apply must be rejected (session already active).
	if _, err := Apply(sessionID, appPath, []string{"203.0.113.11"}); err == nil {
		t.Error("second Apply for same session should fail")
		_ = Revoke(sessionID)
	}

	if err := Revoke(sessionID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	// Revoke of an already-revoked session is a no-op.
	if err := Revoke(sessionID); err != nil {
		t.Errorf("idempotent Revoke: %v", err)
	}
}
