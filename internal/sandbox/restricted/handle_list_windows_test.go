// SPDX-License-Identifier: MIT

//go:build windows

package restricted

// TST-13 — applyHandleListAllowlist input validation.
//
// The success path (UpdateProcThreadAttribute via a real PTAL buffer) requires
// an InitializeProcThreadAttributeList call first, which is wired into the box
// spawn path — that remains e2e.  The error-path and zero-handle filtering
// branches are pure decidable logic tested here.

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestApplyHandleListAllowlist_EmptySliceErrors(t *testing.T) {
	// Zero-length handle list must be rejected before touching the PTAL.
	_, err := applyHandleListAllowlist(nil, []windows.Handle{})
	if err == nil {
		t.Error("empty handle list should return an error")
	}
	if !strings.Contains(err.Error(), "≥1") && !strings.Contains(err.Error(), "requires") {
		t.Errorf("error message should mention the requirement; got %q", err.Error())
	}
}

func TestApplyHandleListAllowlist_NilSliceErrors(t *testing.T) {
	_, err := applyHandleListAllowlist(nil, nil)
	if err == nil {
		t.Error("nil handle list should return an error")
	}
}

func TestApplyHandleListAllowlist_AllZeroHandlesErrors(t *testing.T) {
	// A slice of all-zero handles should be rejected after filtering.
	handles := []windows.Handle{0, 0, 0}
	_, err := applyHandleListAllowlist(nil, handles)
	if err == nil {
		t.Error("all-zero handles should return an error after filtering")
	}
	if !strings.Contains(err.Error(), "zero") {
		t.Errorf("error should mention 'zero' handles; got %q", err.Error())
	}
}

// TestApplyHandleListAllowlist_SuccessPathE2E documents what requires e2e:
// When a PTAL buffer has been properly initialised via InitializeProcThreadAttributeList,
// passing a slice with some zero handles (which get filtered) and at least one
// non-zero valid handle should succeed. This requires a live PTAL context —
// deferred to the box.Start integration path.
//
// Passing a nil listPtr with a valid handle crashes the process (kernel writes
// through the null pointer); that path is NOT tested here. The three tests
// above cover all Go-layer guards that execute before the syscall.
