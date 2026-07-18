// SPDX-License-Identifier: MIT

//go:build windows

package credential

// platformDiscover bridges the generic Discover() call to the Windows-specific
// Credential Manager discovery. See discover_windows.go for implementation.
func platformDiscover(existing []Credential) []Credential {
	return PlatformDiscover(existing)
}
