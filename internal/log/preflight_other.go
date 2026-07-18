// SPDX-License-Identifier: MIT

//go:build !windows

package log

// PreflightWindows is a no-op on non-Windows platforms. The Windows
// preflight inventory inspects dizgin/dizgind binaries, the dizgind
// named pipe, the sensitive SSOT presence, and ~/.dizgin state dirs —
// state that is Windows-specific (named-pipe transport + DACL-driven
// sensitive surface). The seatbelt and bubblewrap backends bring up
// cleanly enough that a separate inventory has not been worth the
// maintenance cost yet. The build-tagged stub keeps callers (dizgin's
// run, dizgind's runDaemon) cross-platform clean.
func PreflightWindows() {}
