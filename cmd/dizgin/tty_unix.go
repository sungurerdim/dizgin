// SPDX-License-Identifier: MIT

//go:build !windows

package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/sungurerdim/dizgin/internal/platform"
	"golang.org/x/sys/unix"
)

// isTerminal reports whether f is a Unix terminal.
func isTerminal(f *os.File) bool {
	return platform.IsTerminal(f)
}

// makeRaw puts the terminal in raw mode and returns a restore function.
// The `out` parameter is accepted for signature parity with the Windows
// implementation (which flips the output handle's ENABLE_VIRTUAL_TERMINAL
// mode) but is not needed on POSIX — the tty is a single fd.
//
// Delegates to platform.SetRaw, which internal/sandbox/posixbox also uses
// to raw-mode the *inner* PTY the sandboxed tool runs under — see that
// function's doc comment for why both sides of the bridge need this.
func makeRaw(in, _ *os.File) (restore func(), err error) {
	return platform.SetRaw(in)
}

// currentTerminalSize returns the current host terminal dimensions.
// Returns (0, 0, false) if the size cannot be determined.
func currentTerminalSize() (uint16, uint16, bool) {
	ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
	if err != nil || ws.Col == 0 || ws.Row == 0 {
		return 0, 0, false
	}
	return ws.Col, ws.Row, true
}

// watchResize listens for SIGWINCH and calls fn with the new terminal dimensions
// whenever the host terminal is resized. Stops when ctx is cancelled.
func watchResize(ctx context.Context, fn func(w, h uint16)) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, unix.SIGWINCH)
	defer signal.Stop(sigCh)
	for {
		select {
		case <-ctx.Done():
			return
		case <-sigCh:
			ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
			if err == nil {
				fn(ws.Col, ws.Row)
			}
		}
	}
}
