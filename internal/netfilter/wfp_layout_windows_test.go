// SPDX-License-Identifier: MIT

//go:build windows

package netfilter

import (
	"testing"
	"unsafe"
)

// The WFP filter path marshals Go structs directly into the fwpuclnt.dll
// ABI. A single wrong offset corrupts the FWPM_FILTER0 the kernel reads,
// so these layout assertions are the machine-checkable signal that the
// struct mirrors match the documented x64 C ABI — independent of whether
// an elevated host is available to exercise the live syscalls.
//
// Expected sizes/offsets derived from the official headers:
//   FWP_VALUE0          = 16  (UINT32 type + 4 pad + 8-byte union)
//   FWPM_FILTER_CONDITION0 = 40 (GUID 16 + matchType 4 + 4 pad + cond 16)
//   FWPM_ACTION0        = 20  (UINT32 type + GUID 16, GUID aligns to 4)
//   FWPM_FILTER0        = 200 (see field-by-field offsets below)

func TestFWPValue0Layout(t *testing.T) {
	if got := unsafe.Sizeof(fwpValue0{}); got != 16 {
		t.Errorf("fwpValue0 size = %d, want 16", got)
	}
	if got := unsafe.Sizeof(fwpConditionValue0{}); got != 16 {
		t.Errorf("fwpConditionValue0 size = %d, want 16", got)
	}
}

func TestFWPMFilterConditionLayout(t *testing.T) {
	var c fwpmFilterCondition0
	if got := unsafe.Sizeof(c); got != 40 {
		t.Errorf("fwpmFilterCondition0 size = %d, want 40", got)
	}
	if got := unsafe.Offsetof(c.matchType); got != 16 {
		t.Errorf("matchType offset = %d, want 16", got)
	}
	if got := unsafe.Offsetof(c.condValue); got != 24 {
		t.Errorf("condValue offset = %d, want 24", got)
	}
}

func TestFWPMActionLayout(t *testing.T) {
	var a fwpmAction0
	if got := unsafe.Sizeof(a); got != 20 {
		t.Errorf("fwpmAction0 size = %d, want 20", got)
	}
	if got := unsafe.Offsetof(a.filterType); got != 4 {
		t.Errorf("filterType offset = %d, want 4", got)
	}
}

func TestFWPMFilter0Layout(t *testing.T) {
	var f fwpmFilter0
	if got := unsafe.Sizeof(f); got != 200 {
		t.Fatalf("fwpmFilter0 size = %d, want 200", got)
	}
	wantOffsets := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"displayData", unsafe.Offsetof(f.displayData), 16},
		{"flags", unsafe.Offsetof(f.flags), 32},
		{"providerKey", unsafe.Offsetof(f.providerKey), 40},
		{"providerData", unsafe.Offsetof(f.providerData), 48},
		{"layerKey", unsafe.Offsetof(f.layerKey), 64},
		{"subLayerKey", unsafe.Offsetof(f.subLayerKey), 80},
		{"weight", unsafe.Offsetof(f.weight), 96},
		{"numFilterConditions", unsafe.Offsetof(f.numFilterConditions), 112},
		{"filterCondition", unsafe.Offsetof(f.filterCondition), 120},
		{"action", unsafe.Offsetof(f.action), 128},
		{"contextUnion", unsafe.Offsetof(f.contextUnion), 152},
		{"reserved", unsafe.Offsetof(f.reserved), 168},
		{"filterID", unsafe.Offsetof(f.filterID), 176},
		{"effectiveWeight", unsafe.Offsetof(f.effectiveWeight), 184},
	}
	for _, o := range wantOffsets {
		if o.got != o.want {
			t.Errorf("%s offset = %d, want %d", o.name, o.got, o.want)
		}
	}
}

func TestFWPMSession0Layout(t *testing.T) {
	var s fwpmSession0
	// sessionKey(16) + displayData(16) + flags(4) + txnWait(4) + procId(4)
	// + 4 pad + sid ptr(8) + username ptr(8) + kernelMode BOOL(4) + 4 pad = 72
	if got := unsafe.Sizeof(s); got != 72 {
		t.Errorf("fwpmSession0 size = %d, want 72", got)
	}
	if got := unsafe.Offsetof(s.sid); got != 48 {
		t.Errorf("sid offset = %d, want 48", got)
	}
}
