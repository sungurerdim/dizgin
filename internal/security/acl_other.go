// SPDX-License-Identifier: MIT

//go:build !windows

package security

// ACL primitives (CurrentUserSID, RevokePathForTrustee) are Windows-only.
// No stubs are needed here because every caller is guarded by a
// //go:build windows tag and the symbols are only declared in acl_windows.go.
