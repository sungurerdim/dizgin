// SPDX-License-Identifier: MIT

//go:build darwin

package credential

// platformDiscover calls macOS-specific Keychain credential discovery.
func platformDiscover(existing []Credential) []Credential {
	return PlatformDiscover(existing)
}
