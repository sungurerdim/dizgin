// SPDX-License-Identifier: MIT

//go:build linux

package daemon

import (
	"net"
	"os"
	"syscall"
)

// peerUID returns the effective UID of the process on the other end of a
// unix-domain socket connection, using SO_PEERCRED. Returns (uid, true) on
// success or (0, false) if the connection is not a unix socket or the
// getsockopt call fails.
func peerUID(nc net.Conn) (uint32, bool) {
	uc, ok := nc.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var cred *syscall.Ucred
	var credErr error
	if ctrlErr := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); ctrlErr != nil {
		return 0, false
	}
	if credErr != nil {
		return 0, false
	}
	return cred.Uid, true
}

// daemonUID returns the effective UID of the running daemon process.
func daemonUID() uint32 {
	return uint32(os.Geteuid())
}
