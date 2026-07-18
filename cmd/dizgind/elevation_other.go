// SPDX-License-Identifier: MIT

//go:build !windows

package main

// ensureElevated is a no-op on non-Windows.
// macOS/Linux sandbox backends don't require elevation.
func ensureElevated() {}
