// SPDX-License-Identifier: MIT

//go:build windows

package daemon

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Microsoft/go-winio"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// pipeName is the Windows named pipe path for the dizgind daemon.
// The pipe is owned by the current user; only processes running as the same
// user can connect (enforced via the DACL in pipeConfig below).
const pipeName = brand.PipeName

// pipeSDDL is a Security Descriptor Definition Language string.
// D:P = protected DACL (no inheritance)
// (A;;GA;;;OW) = Allow Generic-All to Object-Owner.
//
//	When dizgind runs elevated via UAC "runas", the pipe object owner is
//	the user's personal SID — the same SID present in dizgin's non-elevated
//	token. This ACE therefore grants dizgin (non-elevated, same user) full
//	access without opening the pipe to unrelated interactive users.
//
// (A;;GA;;;SY) = Allow Generic-All to SYSTEM for service-level tooling.
//
// The previous IU (Interactive Users) ACE was removed (SEC-01): it allowed
// any locally logged-in user to send privileged daemon commands (TypeShutdown,
// TypeWFPApply, etc.). The owner-based ACE is sufficient because dizgin and dizgind
// share the same user SID regardless of elevation level.
const pipeSDDL = "D:P(A;;GA;;;OW)(A;;GA;;;SY)"

// listen creates a Windows named pipe listener secured to the current user.
// The pipe replaces the previous TCP loopback shim, which had no access control.
func listen() (net.Listener, error) {
	cfg := &winio.PipeConfig{
		SecurityDescriptor: pipeSDDL,
		// MessageMode false = byte-stream pipe (compatible with net.Conn usage).
		MessageMode: false,
		// InputBufferSize and OutputBufferSize: 64 KiB each (adequate for JSON messages).
		InputBufferSize:  65536,
		OutputBufferSize: 65536,
	}
	l, err := winio.ListenPipe(pipeName, cfg)
	if err != nil {
		return nil, fmt.Errorf("transport: ListenPipe %q: %w", pipeName, err)
	}
	return l, nil
}

// dial connects to the dizgind named pipe.
// Uses SECURITY_IMPERSONATION level so the server (dizgind broker) can impersonate
// the client to obtain the user's token for restricted-token sandbox creation.
func dial(timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := winio.DialPipeAccessImpLevel(
		ctx,
		pipeName,
		uint32(0x80000000|0x40000000), // GENERIC_READ | GENERIC_WRITE
		winio.PipeImpLevelImpersonation,
	)
	if err != nil {
		return nil, fmt.Errorf("transport: DialPipe %q: %w", pipeName, err)
	}
	return conn, nil
}
