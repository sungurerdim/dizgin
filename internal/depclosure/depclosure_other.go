// SPDX-License-Identifier: MIT

//go:build !darwin

package depclosure

// parseDeps stays nil on every non-Darwin GOOS today: Resolve() no-ops
// (returns nil) rather than guess. An ELF/DT_NEEDED backend (Linux) is a
// deferred follow-up, not yet implemented — see package doc.
func init() {}
