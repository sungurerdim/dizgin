// SPDX-License-Identifier: MIT

//go:build !darwin && !linux && !windows

package credential

// platformDiscover is a no-op on platforms without dedicated secret stores.
func platformDiscover(_ []Credential) []Credential { return nil }
