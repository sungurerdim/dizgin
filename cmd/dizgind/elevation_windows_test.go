// SPDX-License-Identifier: MIT

//go:build windows

package main

// TST-17 — isElevated / elevation-decision branches.
//
// ensureElevated re-launches the process via ShellExecuteExW (runas verb)
// and calls os.Exit — that path is e2e only (would spawn a UAC prompt or
// exit the test process). We test:
//   - isElevated() returns a consistent bool without panic.
//   - The early-return guard: calling ensureElevated when already elevated
//     must be a no-op (no re-launch). Tested indirectly — if the test
//     runner is elevated, isElevated() must return true and ensureElevated
//     must return without calling os.Exit.
//   - tokenElevation struct layout: field size matches what GetTokenInformation
//     expects (4-byte uint32).

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestIsElevated_ReturnsBoolWithoutPanic verifies the token-query path
// completes without panic regardless of the current elevation state.
func TestIsElevated_ReturnsBoolWithoutPanic(t *testing.T) {
	// Must not panic in either elevated or non-elevated context.
	got := isElevated()
	t.Logf("isElevated() = %v (test runner elevation state)", got)
	// No assertion on the value itself — both true and false are valid
	// depending on whether the test is run as admin.
}

// TestTokenElevationStructSize validates that tokenElevation has the
// correct in-memory footprint that GetTokenInformation expects.
// TOKEN_ELEVATION is defined in winnt.h as { DWORD TokenIsElevated; } — 4 bytes.
func TestTokenElevationStructSize(t *testing.T) {
	var e tokenElevation
	got := unsafe.Sizeof(e)
	const want = 4 // sizeof(DWORD)
	if got != want {
		t.Errorf("tokenElevation size = %d bytes; want %d (sizeof DWORD)", got, want)
	}
}

// TestIsElevated_Consistent verifies two consecutive calls agree — the
// elevation state of a running process does not change mid-execution.
func TestIsElevated_Consistent(t *testing.T) {
	first := isElevated()
	second := isElevated()
	if first != second {
		t.Errorf("isElevated() returned inconsistent results: %v then %v", first, second)
	}
}

// TestIsElevated_MatchesTokenQuery cross-validates isElevated() against
// a direct Windows API call using the documented TokenElevation class (20).
func TestIsElevated_MatchesTokenQuery(t *testing.T) {
	const tokenElevationClass = 20

	token := windows.GetCurrentProcessToken()
	var elev tokenElevation
	n := uint32(unsafe.Sizeof(elev))
	err := windows.GetTokenInformation(
		token, tokenElevationClass,
		(*byte)(unsafe.Pointer(&elev)), n, &n,
	)
	if err != nil {
		// GetTokenInformation may fail in a restricted sandbox — skip rather than fail.
		t.Skipf("GetTokenInformation: %v — skipping cross-validation", err)
	}
	want := elev.TokenIsElevated != 0
	got := isElevated()
	if got != want {
		t.Errorf("isElevated() = %v; direct token query says %v", got, want)
	}
}

// TestEnsureElevated_AlreadyElevatedIsNoop verifies that when the process
// IS elevated, ensureElevated returns immediately without re-launching.
// This cannot be forced (we can't set elevation in a test), so we guard
// with a skip for non-elevated runners.
func TestEnsureElevated_AlreadyElevatedIsNoop(t *testing.T) {
	if !isElevated() {
		t.Skip("test runner is not elevated — ensureElevated no-op path not reachable")
	}
	// If we reach here the process is already elevated.
	// ensureElevated() must return without calling os.Exit or spawning a child.
	// Because it calls os.Exit on failure or returns on success, a panic or
	// exit would fail the test automatically. Just call it.
	ensureElevated() // must return, not exit
	t.Log("ensureElevated() returned normally on an elevated process")
}

// TestEnsureElevated_NonElevatedPath_IsE2E documents what requires e2e.
// When the process is NOT elevated, ensureElevated calls ShellExecuteExW
// with verb="runas" and then os.Exit(). Testing this would exit the test
// runner — deferred to manual / integration test.
func TestEnsureElevated_NonElevatedPath_IsE2E(t *testing.T) {
	if isElevated() {
		t.Skip("process is already elevated — non-elevated path not applicable")
	}
	t.Skip("e2e: non-elevated ensureElevated spawns ShellExecuteExW + os.Exit — manual only")
}
