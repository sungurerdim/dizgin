// SPDX-License-Identifier: MIT

//go:build !windows

package main

// redirectDaemonOutput is a no-op on non-Windows: the daemon there runs
// from a normal terminal where stdout/stderr are visible and journald /
// systemd capture them when run as a service.
func redirectDaemonOutput() {}
