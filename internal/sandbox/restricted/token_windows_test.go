// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"testing"
)

// TestCreateRestrictedTokenMediumIL is the Faz 1 acceptance test for
// the iter6 token refactor. It verifies that CreateRestrictedTokenMediumIL
// produces a token whose mandatory integrity label is exactly Medium
// (S-1-16-8192), not the iter5 default of Low (S-1-16-4096).
//
// We assert on the SID string rather than a parsed IL level because
// it is the most direct evidence the SetTokenInformation(IntegrityLevel)
// call inside CreateRestrictedTokenForLevel actually stuck — any
// regression in the constants table or the IL setter will fail here.
func TestCreateRestrictedTokenMediumIL(t *testing.T) {
	tok, err := CreateRestrictedTokenMediumIL()
	if err != nil {
		t.Fatalf("CreateRestrictedTokenMediumIL: %v", err)
	}
	defer func() { _ = tok.Close() }()

	sid, err := TokenIntegrityLevelSID(tok)
	if err != nil {
		t.Fatalf("TokenIntegrityLevelSID: %v", err)
	}
	if sid != IntegrityLevelMediumSid {
		t.Fatalf("integrity level SID mismatch: want %q, got %q",
			IntegrityLevelMediumSid, sid)
	}
}

// TestCreateRestrictedTokenForLevel_Low covers the parametric path with
// Low IL — what iter5's AppContainer fork would have produced. Proves
// the helper is genuinely level-agnostic rather than hard-wiring Medium.
func TestCreateRestrictedTokenForLevel_Low(t *testing.T) {
	tok, err := CreateRestrictedTokenForLevel(IntegrityLevelLowSid)
	if err != nil {
		t.Fatalf("CreateRestrictedTokenForLevel(Low): %v", err)
	}
	defer func() { _ = tok.Close() }()

	sid, err := TokenIntegrityLevelSID(tok)
	if err != nil {
		t.Fatalf("TokenIntegrityLevelSID: %v", err)
	}
	if sid != IntegrityLevelLowSid {
		t.Fatalf("integrity level SID mismatch: want %q, got %q",
			IntegrityLevelLowSid, sid)
	}
}
