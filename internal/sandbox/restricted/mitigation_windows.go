// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Process mitigation policy wiring for the iter6 `restricted` backend.
//
// Two delivery paths exist for Windows process mitigations:
//
//  1. SetProcessMitigationPolicy — applies to the *current* process.
//     One-way switches: once a policy is enabled, it cannot be turned
//     off without re-spawning. Useful for dizgin itself if we ever want
//     to harden the parent, but not for the sandbox child.
//
//  2. PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY — applied via the
//     PTAL on CreateProcessAsUserW. The kernel reads a DWORD64 (or
//     DWORD64[2] on Win10 19H1+ for POLICY2 bits) and enforces the
//     listed mitigations on the spawned process from image-load time.
//     This is the production path used by box_windows.go.
//
// The bitfield layout is documented in winbase.h under
// PROCESS_CREATION_MITIGATION_POLICY_*. We deliberately keep the
// constant names verbose so a grep against MSDN works directly.
var procGetProcessMitigationPolicy = modKernel32.NewProc("GetProcessMitigationPolicy")

// PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY encoded value. Same encoding
// rule as PROC_THREAD_ATTRIBUTE_HANDLE_LIST (see handle_list_windows.go).
// ProcThreadAttributeMitigationPolicy = 7, FALSE/TRUE/FALSE → 0x00020007.
const procThreadAttributeMitigationPolicy = 0x00020007

// PROCESS_CREATION_MITIGATION_POLICY_* bits — DWORD64, low qword.
// Reference: winbase.h. Each bit lives at a fixed 4-bit-aligned shift
// (ALWAYS_ON occupies the lowest of the 4-bit slot). We use `1 << N`
// rather than hex literals so the offset matches the MSDN docs at a
// glance and a typo collapses to a build error rather than a silent
// bit collision.
const (
	// DEP — Data Execution Prevention. ALWAYS_ON forces NX on every
	// data page; cannot be disabled by the child once set at spawn.
	pcmpDEPEnable                   uint64 = 1 << 0
	pcmpDEPATLThunkEmulationDisable uint64 = 1 << 2

	// ASLR — Address Space Layout Randomization.
	pcmpForceRelocateImagesAlwaysOn uint64 = 1 << 8  // FORCE_RELOCATE_IMAGES_ALWAYS_ON
	pcmpBottomUpASLRAlwaysOn        uint64 = 1 << 16 // BOTTOM_UP_ASLR_ALWAYS_ON
	pcmpHighEntropyASLRAlwaysOn     uint64 = 1 << 20 // HIGH_ENTROPY_ASLR_ALWAYS_ON

	// Strict handle check — invalid handle = exception. Catches use-
	// after-close bugs early and denies a class of probing tricks.
	pcmpStrictHandleChecksAlwaysOn uint64 = 1 << 24

	// Dynamic Code (ACG — Arbitrary Code Guard). PROHIBIT blocks
	// VirtualAlloc(RWX), VirtualProtect(RWX), and dynamic JIT.
	//
	// We INTENTIONALLY DO NOT set this bit by default. Bun ships an
	// in-process JavaScriptCore JIT; ACG blocks the JIT at first
	// allocation and the runtime wedges. This is the iter5
	// CLAUDE-HANG-01 root cause. Edge solved the same problem with
	// an out-of-process JIT server; DIZGIN's deployment model cannot
	// justify that investment.
	pcmpProhibitDynamicCodeAlwaysOn uint64 = 1 << 36

	// BlockNonMicrosoftBinaries — only Microsoft-signed binaries may
	// load into the process. Opt-in (profile flag) because it breaks
	// most third-party tools by design.
	pcmpBlockNonMicrosoftBinariesAlwaysOn uint64 = 1 << 44

	// Image Load hardening.
	pcmpImageLoadNoRemoteAlwaysOn       uint64 = 1 << 52 // NO_REMOTE (block UNC-DLL injection)
	pcmpImageLoadNoLowLabelAlwaysOn     uint64 = 1 << 56 // NO_LOW_MANDATORY_LABEL
	pcmpImageLoadPreferSystem32AlwaysOn uint64 = 1 << 60 // PREFER_SYSTEM32 over caller dir
)

// Policies captures the iter6 default mitigation set. Booleans map
// directly to PROCESS_CREATION_MITIGATION_POLICY_* bits so callers
// (including profile YAML) can express intent without touching the
// raw bitfield.
type Policies struct {
	// DEP — always recommended; cost is negligible. Default ON.
	DEP bool
	// ASLR ForceRelocate + HighEntropy + BottomUp. Default ON.
	ASLR bool
	// ProhibitDynamicCode (ACG). KEEP FALSE for Bun compatibility.
	// Setting this true breaks Claude Code (Bun SEA), Node experimental
	// JIT users, and any tool with a JIT runtime. Documented escape
	// hatch for non-Bun profiles that want the extra hardening.
	ProhibitDynamicCode bool
	// BlockNonMicrosoftBinaries — opt-in only. Breaks most dev tools.
	BlockNonMicrosoftBinaries bool
	// StrictHandleChecks — catches handle misuse early. Default ON;
	// Bun + Node tolerate this; cost is one extra exception path.
	StrictHandleChecks bool
	// ImageLoadHardening: NoRemote + NoLowLabel + PreferSystem32.
	// Default ON; blocks UNC-DLL injection vectors with no app cost
	// for tools running from the local filesystem.
	ImageLoadHardening bool
}

// DefaultPolicies returns the iter6 baseline. Bun-compatible: ACG is
// OFF, BlockNonMicrosoftBinaries is OFF. Everything else hardened.
func DefaultPolicies() Policies {
	return Policies{
		DEP:                       true,
		ASLR:                      true,
		ProhibitDynamicCode:       false,
		BlockNonMicrosoftBinaries: false,
		StrictHandleChecks:        true,
		ImageLoadHardening:        true,
	}
}

// Bitfield encodes p into the DWORD64 the kernel reads from the PTAL
// PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY buffer.
//
// Returns (flags, 0) — the high qword (POLICY2 bits) is unused by
// the current iter6 default set. When BlockNonMicrosoftBinaries gains
// finer-grained control on Win10 RS5+, the second qword opens up.
func (p Policies) Bitfield() uint64 {
	var f uint64
	if p.DEP {
		f |= pcmpDEPEnable | pcmpDEPATLThunkEmulationDisable
	}
	if p.ASLR {
		f |= pcmpForceRelocateImagesAlwaysOn | pcmpHighEntropyASLRAlwaysOn | pcmpBottomUpASLRAlwaysOn
	}
	if p.ProhibitDynamicCode {
		f |= pcmpProhibitDynamicCodeAlwaysOn
	}
	if p.StrictHandleChecks {
		f |= pcmpStrictHandleChecksAlwaysOn
	}
	if p.ImageLoadHardening {
		f |= pcmpImageLoadNoRemoteAlwaysOn | pcmpImageLoadNoLowLabelAlwaysOn | pcmpImageLoadPreferSystem32AlwaysOn
	}
	if p.BlockNonMicrosoftBinaries {
		f |= pcmpBlockNonMicrosoftBinariesAlwaysOn
	}
	return f
}

// applyChildMitigationPTAL registers a PROC_THREAD_ATTRIBUTE_MITIGATION_
// POLICY entry on the supplied PTAL so the kernel enforces p on the
// spawned child from image-load time. The flag buffer must remain
// addressable until CreateProcessAsUserW returns; the returned uint64
// is the caller-owned backing store (callers should hold it alive via
// runtime.KeepAlive through the spawn).
func applyChildMitigationPTAL(listPtr unsafe.Pointer, p Policies) (*uint64, error) {
	flags := p.Bitfield()
	if flags == 0 {
		return nil, fmt.Errorf("mitigation: empty policy set")
	}
	if r, _, e := procUpdateProcThreadAttribute.Call(
		uintptr(listPtr),
		0,
		uintptr(procThreadAttributeMitigationPolicy),
		uintptr(unsafe.Pointer(&flags)),
		unsafe.Sizeof(flags),
		0,
		0,
	); r == 0 {
		return nil, fmt.Errorf("UpdateProcThreadAttribute(MITIGATION_POLICY): %w", e)
	}
	return &flags, nil
}

// ProcessMitigationPolicyClass values from winbase.h. We expose the two
// classes Phase 1 tests touch; the full enum is large and adding
// constants on demand keeps surface honest.
const (
	processDEPPolicy               = 0
	processASLRPolicy              = 1
	processDynamicCodePolicy       = 2
	processStrictHandleCheckPolicy = 3
)

// processMitigationDEPPolicy mirrors PROCESS_MITIGATION_DEP_POLICY from
// winnt.h. Layout: 32-bit flags + Permanent BOOLEAN + padding.
type processMitigationDEPPolicy struct {
	Flags     uint32 // bit 0: Enable, bit 1: DisableAtlThunkEmulation
	Permanent uint8
	_         [3]uint8
}

// processMitigationASLRPolicy mirrors PROCESS_MITIGATION_ASLR_POLICY.
// bit 0: EnableBottomUpRandomization, bit 1: EnableForceRelocateImages,
// bit 2: EnableHighEntropy, bit 3: DisallowStrippedImages.
type processMitigationASLRPolicy struct {
	Flags uint32
}

// processMitigationDynamicCodePolicy mirrors PROCESS_MITIGATION_
// DYNAMIC_CODE_POLICY. bit 0: ProhibitDynamicCode.
type processMitigationDynamicCodePolicy struct {
	Flags uint32
}

// GetCurrentProcessDEP queries DEP state on the current process.
// Returns (enabled, permanent, error). Used by Phase 1 tests to
// confirm the GetProcessMitigationPolicy wiring is live.
func GetCurrentProcessDEP() (enabled, permanent bool, err error) {
	var pol processMitigationDEPPolicy
	r, _, e := procGetProcessMitigationPolicy.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(processDEPPolicy),
		uintptr(unsafe.Pointer(&pol)),
		unsafe.Sizeof(pol),
	)
	if r == 0 {
		return false, false, fmt.Errorf("GetProcessMitigationPolicy(DEP): %w", e)
	}
	return pol.Flags&0x1 != 0, pol.Permanent != 0, nil
}

// GetCurrentProcessASLR queries ASLR state on the current process.
func GetCurrentProcessASLR() (bottomUp, forceRelocate, highEntropy bool, err error) {
	var pol processMitigationASLRPolicy
	r, _, e := procGetProcessMitigationPolicy.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(processASLRPolicy),
		uintptr(unsafe.Pointer(&pol)),
		unsafe.Sizeof(pol),
	)
	if r == 0 {
		return false, false, false, fmt.Errorf("GetProcessMitigationPolicy(ASLR): %w", e)
	}
	return pol.Flags&0x1 != 0, pol.Flags&0x2 != 0, pol.Flags&0x4 != 0, nil
}

// GetCurrentProcessDynamicCode queries ACG state on the current process.
// Returns true when ProhibitDynamicCode is ON — for the dizgin parent we
// expect FALSE (the parent runs as a regular user process).
func GetCurrentProcessDynamicCode() (prohibit bool, err error) {
	var pol processMitigationDynamicCodePolicy
	r, _, e := procGetProcessMitigationPolicy.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(processDynamicCodePolicy),
		uintptr(unsafe.Pointer(&pol)),
		unsafe.Sizeof(pol),
	)
	if r == 0 {
		return false, fmt.Errorf("GetProcessMitigationPolicy(DynamicCode): %w", e)
	}
	return pol.Flags&0x1 != 0, nil
}
