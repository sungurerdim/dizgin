// SPDX-License-Identifier: MIT

//go:build windows

package restricted

// TST-15 — overridesEqual / slicesEqualFold set-equality logic.
//
// maybePromptAndSavePermissions is not tested here because it drives
// os.Stdin/os.Stderr and file I/O together; that interaction is covered
// by the permissions_windows_test.go round-trip suite.  The pure
// comparison helpers are fully testable and high-value.

import "testing"

// ---- slicesEqualFold ----

func TestSlicesEqualFold_BothNil(t *testing.T) {
	if !slicesEqualFold(nil, nil) {
		t.Error("nil == nil should be true")
	}
}

func TestSlicesEqualFold_BothEmpty(t *testing.T) {
	if !slicesEqualFold([]string{}, []string{}) {
		t.Error("empty == empty should be true")
	}
}

func TestSlicesEqualFold_NilAndEmpty(t *testing.T) {
	// nil and []string{} have the same length (0) and same content.
	if !slicesEqualFold(nil, []string{}) {
		t.Error("nil and empty slice should be equal (same length 0)")
	}
}

func TestSlicesEqualFold_SameLengthSameOrder(t *testing.T) {
	a := []string{`c:\users\me\.ssh`, `c:\users\me\.aws`}
	b := []string{`c:\users\me\.ssh`, `c:\users\me\.aws`}
	if !slicesEqualFold(a, b) {
		t.Error("identical slices should be equal")
	}
}

func TestSlicesEqualFold_SameLengthDifferentOrder(t *testing.T) {
	a := []string{`c:\users\me\.aws`, `c:\users\me\.ssh`}
	b := []string{`c:\users\me\.ssh`, `c:\users\me\.aws`}
	if !slicesEqualFold(a, b) {
		t.Error("same elements in different order should be equal (set semantics)")
	}
}

func TestSlicesEqualFold_CaseInsensitive(t *testing.T) {
	a := []string{`C:\Users\Me\.SSH`}
	b := []string{`c:\users\me\.ssh`}
	if !slicesEqualFold(a, b) {
		t.Error("case-insensitive match should be equal")
	}
}

func TestSlicesEqualFold_DifferentLengths(t *testing.T) {
	a := []string{`c:\users\me\.ssh`}
	b := []string{`c:\users\me\.ssh`, `c:\users\me\.aws`}
	if slicesEqualFold(a, b) {
		t.Error("different lengths should not be equal")
	}
}

func TestSlicesEqualFold_SameLengthDifferentContent(t *testing.T) {
	a := []string{`c:\users\me\.ssh`}
	b := []string{`c:\users\me\.gnupg`}
	if slicesEqualFold(a, b) {
		t.Error("different content should not be equal")
	}
}

func TestSlicesEqualFold_DuplicatesMustNotFoolMatcher(t *testing.T) {
	// a has two identical entries; b has one unique entry — lengths differ,
	// so they should not be equal.
	a := []string{`c:\users\me\.ssh`, `c:\users\me\.ssh`}
	b := []string{`c:\users\me\.ssh`}
	if slicesEqualFold(a, b) {
		t.Error("a with duplicates vs b with one entry: length differs, should not be equal")
	}
}

func TestSlicesEqualFold_ThreeElements(t *testing.T) {
	a := []string{`c:\a`, `c:\b`, `c:\c`}
	b := []string{`C:\C`, `C:\A`, `C:\B`}
	if !slicesEqualFold(a, b) {
		t.Error("three-element sets in different order should be equal")
	}
}

// ---- overridesEqual ----

func TestOverridesEqual_BothEmpty(t *testing.T) {
	if !overridesEqual(Overrides{}, Overrides{}) {
		t.Error("empty Overrides should be equal")
	}
}

func TestOverridesEqual_Identical(t *testing.T) {
	a := Overrides{
		RW:   []string{`c:\users\me\projects`},
		RO:   []string{`c:\windows\system32\foo.dll`},
		Deny: []string{`c:\users\me\.gnupg`},
	}
	b := Overrides{
		RW:   []string{`c:\users\me\projects`},
		RO:   []string{`c:\windows\system32\foo.dll`},
		Deny: []string{`c:\users\me\.gnupg`},
	}
	if !overridesEqual(a, b) {
		t.Error("identical Overrides should be equal")
	}
}

func TestOverridesEqual_OrderIndependent(t *testing.T) {
	a := Overrides{
		RW: []string{`c:\users\me\projects`, `c:\users\me\work`},
		RO: []string{`c:\windows\system32\ntdll.dll`, `c:\windows\system32\kernel32.dll`},
	}
	b := Overrides{
		RW: []string{`c:\users\me\work`, `c:\users\me\projects`},
		RO: []string{`c:\windows\system32\kernel32.dll`, `c:\windows\system32\ntdll.dll`},
	}
	if !overridesEqual(a, b) {
		t.Error("Overrides with same entries in different order should be equal")
	}
}

func TestOverridesEqual_CaseInsensitive(t *testing.T) {
	a := Overrides{RW: []string{`C:\Users\Me\Projects`}}
	b := Overrides{RW: []string{`c:\users\me\projects`}}
	if !overridesEqual(a, b) {
		t.Error("case-insensitive RW entries should be equal")
	}
}

func TestOverridesEqual_DifferentRWCount(t *testing.T) {
	a := Overrides{RW: []string{`c:\users\me\a`, `c:\users\me\b`}}
	b := Overrides{RW: []string{`c:\users\me\a`}}
	if overridesEqual(a, b) {
		t.Error("different RW counts should not be equal")
	}
}

func TestOverridesEqual_DifferentDenySet(t *testing.T) {
	a := Overrides{Deny: []string{`c:\users\me\.gnupg`}}
	b := Overrides{Deny: []string{`c:\users\me\.ssh`}}
	if overridesEqual(a, b) {
		t.Error("different Deny sets should not be equal")
	}
}

func TestOverridesEqual_RWvsROMismatch(t *testing.T) {
	// Same path appears in RW for a but RO for b — the slices are
	// compared independently, so they should not be equal.
	a := Overrides{RW: []string{`c:\users\me\projects`}, RO: nil}
	b := Overrides{RW: nil, RO: []string{`c:\users\me\projects`}}
	if overridesEqual(a, b) {
		t.Error("path in RW vs path in RO should not be equal")
	}
}

func TestOverridesEqual_SaveGateShortCircuit(t *testing.T) {
	// Simulate the save-gate: if existing == updated, no save should happen.
	// We verify overridesEqual is the right predicate for this decision.
	existing := Overrides{
		RW: []string{`c:\users\me\projects\myapp`},
		RO: []string{`c:\windows\system32\ntdll.dll`},
	}
	// updated is a copy with the same values (what PromptForPermissions
	// returns on non-TTY stdin — it clones but does not add).
	updated := Overrides{
		RW: append([]string{}, existing.RW...),
		RO: append([]string{}, existing.RO...),
	}
	if !overridesEqual(existing, updated) {
		t.Error("cloned Overrides should be equal — save gate would incorrectly fire")
	}
}
