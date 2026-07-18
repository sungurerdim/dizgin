// SPDX-License-Identifier: MIT

//go:build !windows

package main

// ensureDaemonRunning is a no-op on non-Windows.
// macOS/Linux sandbox backends don't require a daemon.
func ensureDaemonRunning() {}
