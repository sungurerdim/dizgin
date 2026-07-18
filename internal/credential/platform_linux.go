// SPDX-License-Identifier: MIT

//go:build linux

package credential

// platformDiscover calls Linux-specific GNOME Keyring credential discovery.
func platformDiscover(existing []Credential) []Credential {
	return PlatformDiscover(existing)
}
