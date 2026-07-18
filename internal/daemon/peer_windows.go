// SPDX-License-Identifier: MIT

//go:build windows

package daemon

import "net"

// peerUID is not used on Windows. Authorization is enforced at connection
// time by the named-pipe DACL (pipeSDDL in transport_windows.go), which
// restricts callers to the pipe owner and SYSTEM. Any connection that
// reaches handleConn has already been validated by the OS before the
// handle is returned from AcceptPipe. A per-message impersonation check
// via ImpersonateNamedPipeClient + GetTokenInformation is possible but
// adds syscall overhead without meaningfully raising the security bar,
// because the DACL already prevents cross-user access.
func peerUID(_ net.Conn) (uint32, bool) {
	return 0, false
}

// daemonUID is a stub on Windows (unused; peerUID always returns ok=false).
func daemonUID() uint32 {
	return 0
}
