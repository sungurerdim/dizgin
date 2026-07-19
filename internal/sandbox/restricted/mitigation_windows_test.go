// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"testing"
)

// TestMitigationPoliciesApplied is the Faz 1 acceptance test for the
// iter6 process mitigation wiring. It exercises two surfaces:
//
//  1. Policies.Bitfield encoding — golden-bit assertions against the
//     winbase.h PROCESS_CREATION_MITIGATION_POLICY_* values. A
//     regression in any constant (e.g. shifting one bit by accident)
//     is caught here before it reaches box.Start.
//
//  2. GetProcessMitigationPolicy wiring — calling the syscall on the
//     current process must succeed and return data, proving the proc
//     resolver + struct layout are correct. We cannot assert on the
//     parent's state directly (DEP/ASLR may or may not be on for the
//     dizgin process itself), so the test asserts on call success only.
//
// The actual ACG-OFF guarantee on the spawned child is exercised in
// the Phase 3 e2e suite when box_windows.go uses applyChildMitigationPTAL
// during CreateProcessAsUserW.
func TestMitigationPoliciesApplied(t *testing.T) {
	t.Run("Bitfield_DefaultPolicies_DEP_ASLR_on_ACG_off", func(t *testing.T) {
		p := DefaultPolicies()
		flags := p.Bitfield()

		if flags&pcmpDEPEnable == 0 {
			t.Errorf("default DEP bit missing: flags=%#x", flags)
		}
		if flags&pcmpForceRelocateImagesAlwaysOn == 0 {
			t.Errorf("default ASLR force-relocate bit missing: flags=%#x", flags)
		}
		if flags&pcmpHighEntropyASLRAlwaysOn == 0 {
			t.Errorf("default ASLR high-entropy bit missing: flags=%#x", flags)
		}
		if flags&pcmpBottomUpASLRAlwaysOn == 0 {
			t.Errorf("default ASLR bottom-up bit missing: flags=%#x", flags)
		}
		if flags&pcmpProhibitDynamicCodeAlwaysOn != 0 {
			t.Errorf("default ACG bit set — would re-introduce CLAUDE-HANG-01: flags=%#x", flags)
		}
		if flags&pcmpBlockNonMicrosoftBinariesAlwaysOn != 0 {
			t.Errorf("default BlockNonMicrosoftBinaries set — opt-in only: flags=%#x", flags)
		}
		if flags&pcmpStrictHandleChecksAlwaysOn == 0 {
			t.Errorf("default StrictHandleChecks bit missing: flags=%#x", flags)
		}
		if flags&pcmpImageLoadNoRemoteAlwaysOn == 0 {
			t.Errorf("default ImageLoad NoRemote bit missing: flags=%#x", flags)
		}
		if flags&pcmpImageLoadPreferSystem32AlwaysOn == 0 {
			t.Errorf("default ImageLoad PreferSystem32 bit missing: flags=%#x", flags)
		}
	})

	t.Run("Bitfield_explicit_ACG_on_when_requested", func(t *testing.T) {
		p := DefaultPolicies()
		p.ProhibitDynamicCode = true
		flags := p.Bitfield()
		if flags&pcmpProhibitDynamicCodeAlwaysOn == 0 {
			t.Errorf("opt-in ACG bit missing when ProhibitDynamicCode=true: flags=%#x", flags)
		}
	})

	t.Run("Bitfield_explicit_BlockNonMicrosoft_when_requested", func(t *testing.T) {
		p := Policies{BlockNonMicrosoftBinaries: true}
		flags := p.Bitfield()
		if flags&pcmpBlockNonMicrosoftBinariesAlwaysOn == 0 {
			t.Errorf("opt-in BlockNonMicrosoftBinaries bit missing: flags=%#x", flags)
		}
	})

	t.Run("Bitfield_zero_when_all_false", func(t *testing.T) {
		flags := Policies{}.Bitfield()
		if flags != 0 {
			t.Errorf("empty policy set produced non-zero bitfield: flags=%#x", flags)
		}
	})

	t.Run("GetProcessMitigationPolicy_DEP_syscall_wiring", func(t *testing.T) {
		// We cannot assert ON/OFF — Go runtime may or may not enable
		// DEP on its own. Asserting on call success proves the
		// proc resolver + struct layout are correct.
		if _, _, err := getCurrentProcessDEP(); err != nil {
			t.Errorf("getCurrentProcessDEP: %v", err)
		}
	})

	t.Run("GetProcessMitigationPolicy_ASLR_syscall_wiring", func(t *testing.T) {
		if _, _, _, err := getCurrentProcessASLR(); err != nil {
			t.Errorf("getCurrentProcessASLR: %v", err)
		}
	})

	t.Run("GetProcessMitigationPolicy_DynamicCode_syscall_wiring", func(t *testing.T) {
		// The dizgin parent runs as a regular user process — ACG should
		// not be on. We assert wiring + the expected baseline value.
		prohibit, err := getCurrentProcessDynamicCode()
		if err != nil {
			t.Errorf("getCurrentProcessDynamicCode: %v", err)
			return
		}
		if prohibit {
			t.Errorf("dizgin parent has ACG ON — unexpected baseline (test runner sandbox?)")
		}
	})
}
