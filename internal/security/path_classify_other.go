// SPDX-License-Identifier: MIT

//go:build !windows

package security

// Non-Windows stubs for the path classifier so cmd/dizgin/mounts.go and any
// other cross-platform caller compiles on darwin/linux. The restricted
// backend is Windows-only; on other platforms these classifiers have no
// semantic meaning — Seatbelt and bubblewrap make their own mount
// decisions without consulting NTFS-shaped concepts like system roots,
// volume roots, or mandatory integrity levels.
//
// Callers that gate Windows-specific behavior on these helpers will see
// a conservative "no" answer here, which matches the intent: nothing on
// Unix is "the OS-managed dir whose inbox grant covers it" or "a volume
// root that admin can't DACL-modify".

// IsSystemPath always returns false on non-Windows. The Windows
// implementation flags OS-managed directories (System32, Program Files,
// ProgramData) where the inbox grant already covers traversal; Unix has
// no equivalent — mount lists on Unix are platform-specific concerns of
// the Seatbelt / bubblewrap backends.
func IsSystemPath(host string) bool { return false }

// IsVolumeRoot always returns false on non-Windows. Volume roots are a
// Windows concept (drive letters like "C:\"); Unix has a single root
// and the classifier never needs to flag it specially.
func IsVolumeRoot(dir string) bool { return false }

// IsIntegrityDenied always returns (false, "") on non-Windows. Mandatory
// integrity levels are a Windows ACE concept with no Unix equivalent.
func IsIntegrityDenied(dir string) (bool, string) { return false, "" }

// DirContainsExecutable always returns false on non-Windows. The
// Windows version exists as a fail-closed guard for the integrity-label
// denylist; non-Windows callers gate on platform earlier in the chain.
func DirContainsExecutable(dir string) bool { return false }
