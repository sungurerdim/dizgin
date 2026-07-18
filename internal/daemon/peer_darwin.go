// SPDX-License-Identifier: MIT

//go:build darwin

package daemon

import (
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// peerUID returns the effective UID of the process on the other end of a
// unix-domain socket connection, using LOCAL_PEERCRED/Xucred on Darwin.
// Returns (uid, true) on success or (0, false) if the connection is not a
// unix socket or the getsockopt call fails.
func peerUID(nc net.Conn) (uint32, bool) {
	uc, ok := nc.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var xucred *unix.Xucred
	var credErr error
	if ctrlErr := raw.Control(func(fd uintptr) {
		xucred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); ctrlErr != nil {
		return 0, false
	}
	if credErr != nil {
		return 0, false
	}
	return xucred.Uid, true
}

// daemonUID returns the effective UID of the running daemon process.
func daemonUID() uint32 {
	return uint32(os.Geteuid())
}
