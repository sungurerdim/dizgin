// SPDX-License-Identifier: MIT

//go:build windows

package security

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// CurrentUserSID returns the SID of the process token's user. Wraps
// OpenProcessToken + GetTokenUser so callers do not need to manage the
// token handle. Returned SID is allocated via Go heap and remains valid
// for the caller's lifetime.
//
// Exposed from internal/security rather than internal/sandbox/restricted
// so cmd/dizgind and other packages can use it without importing the
// concrete backend package (ARC-05).
func CurrentUserSID() (*windows.SID, error) {
	var tok windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_QUERY,
		&tok,
	); err != nil {
		return nil, fmt.Errorf("security: OpenProcessToken: %w", err)
	}
	defer func() { _ = tok.Close() }()

	user, err := tok.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("security: GetTokenUser: %w", err)
	}
	// Copy the SID off the syscall struct — the underlying memory is owned
	// by the token handle, which Close() releases on return.
	sid, err := user.User.Sid.Copy()
	if err != nil {
		return nil, fmt.Errorf("security: Sid.Copy: %w", err)
	}
	return sid, nil
}

// RevokePathForTrustee removes every ACE whose trustee SID matches
// trustee from the DACL of dir and its descendants. It is wired by
// internal/sandbox/restricted's init() so the implementation stays in the
// restricted package (which owns the stamping ACL machinery) while the
// public seam lives here in internal/security (ARC-05). cmd/dizgind heal
// calls this without importing restricted.
//
// The function variable is nil until internal/sandbox/restricted is
// imported (via its init). Code that runs before the restricted backend's
// init() fires must not call this (dizgin / dizgind both import the backend
// package at startup via the platform blank-import chain).
var RevokePathForTrustee func(dir string, trustee *windows.SID) error
