// SPDX-License-Identifier: MIT

//go:build !windows

package platform

import (
	"os"

	"golang.org/x/sys/unix"
)

// IsTerminal reports whether f is a Unix terminal.
func IsTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), ioctlReadTermios)
	return err == nil
}

// IsRaw reports whether f's tty currently has canonical-mode line editing
// and echo disabled — i.e. has been put in raw mode by SetRaw or
// equivalent. Exported mainly so callers (including tests) can assert raw
// mode actually took effect without duplicating the platform-specific
// ioctl constants this file keeps private.
func IsRaw(f *os.File) (bool, error) {
	termios, err := unix.IoctlGetTermios(int(f.Fd()), ioctlReadTermios)
	if err != nil {
		return false, err
	}
	return termios.Lflag&(unix.ICANON|unix.ECHO) == 0, nil
}

// SetRaw puts f's tty in raw mode (equivalent to cfmakeraw — portable
// across Linux and Darwin) and returns a function that restores the
// original termios. Shared by two callers that both need it for the same
// reason — keystrokes must reach the reading process immediately, with no
// kernel line-editing or echo in between — but on opposite sides of the
// PTY dizgin bridges: cmd/dizgin puts the host's real terminal in raw mode
// so it can forward keypresses byte-for-byte, and internal/sandbox/posixbox
// puts the *inner* PTY (the sandboxed tool's controlling terminal) in raw
// mode before the tool's own runtime gets a chance to. Without the latter,
// the inner PTY starts in the kernel's default cooked mode (ICANON+ECHO
// on), and anything written into it before the sandboxed tool flips raw
// mode itself — including terminal capability query/responses dizgin is
// transparently relaying — gets echoed straight back out by the line
// discipline instead of being consumed as input, rendering as garbled text
// mid-frame and swallowing single keypresses that need a trailing newline
// to flush the canonical-mode line buffer.
func SetRaw(f *os.File) (restore func(), err error) {
	fd := int(f.Fd())
	termios, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	if err != nil {
		return nil, err
	}
	orig := *termios

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
