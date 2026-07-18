// SPDX-License-Identifier: MIT

//go:build !linux && !darwin && !windows

package daemon

import "net"

// peerUID is not implemented on this platform. Returns (0, false) so the
// caller treats the check as "not available" and skips uid enforcement.
// The socket is still protected by OS-level permissions (e.g. 0600 mode).
func peerUID(_ net.Conn) (uint32, bool) {
	return 0, false
}

// daemonUID is a stub for unsupported platforms.
func daemonUID() uint32 {
	return 0
}
