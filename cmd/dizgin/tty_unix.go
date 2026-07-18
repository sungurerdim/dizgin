// SPDX-License-Identifier: MIT

//go:build !windows

package main

import (
	"context"
	"os"
	"os/signal"

	"golang.org/x/sys/unix"
)

// isTerminal reports whether f is a Unix terminal.
func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), ioctlReadTermios)
	return err == nil
}

// makeRaw puts the terminal in raw mode and returns a restore function.
// The `out` parameter is accepted for signature parity with the Windows
// implementation (which flips the output handle's ENABLE_VIRTUAL_TERMINAL
// mode) but is not needed on POSIX — the tty is a single fd.
func makeRaw(in, _ *os.File) (restore func(), err error) {
	fd := int(in.Fd())
	termios, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	if err != nil {
		return nil, err
	}
	orig := *termios

	// Set raw mode (equivalent to cfmakeraw — portable across Linux and Darwin).
	raw := orig
	raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	raw.Oflag &^= unix.OPOST
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Cflag &^= unix.CSIZE | unix.PARENB
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0

	if err = unix.IoctlSetTermios(fd, ioctlWriteTermios, &raw); err != nil {
		return nil, err
	}
	restore = func() {
		unix.IoctlSetTermios(fd, ioctlWriteTermios, &orig) //nolint:errcheck
	}
	return restore, nil
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
