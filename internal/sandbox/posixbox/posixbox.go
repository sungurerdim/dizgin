// SPDX-License-Identifier: MIT

//go:build darwin || linux

// Package posixbox provides the process-lifecycle plumbing shared by the
// two POSIX sandbox backends (seatbelt on macOS, bubblewrap on Linux):
// PTY allocation via creack/pty and the exec.Cmd-based Wait/Signal/Pid/PTY
// primitives every sandbox.Box implementation needs regardless of how the
// child was launched. Each backend embeds Lifecycle and supplies its own
// Start/Cleanup — profile/argv construction and teardown differ completely
// between sandbox-exec and bwrap.
package posixbox

import (
	"io"
	"os"
	"os/exec"
	"sync"

	"github.com/creack/pty"
)

// PTYSession holds the host-side PTY file for a sandboxed process.
type PTYSession struct {
	ptmx *os.File
}

// StartWithPTY starts cmd under a PTY and returns the host-side PTY file.
// The caller is responsible for closing the returned session.
func StartWithPTY(cmd *exec.Cmd) (*PTYSession, error) {
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, err
	}
	return &PTYSession{ptmx: ptmx}, nil
}

// RWC returns the io.ReadWriteCloser for the host side of the PTY.
func (p *PTYSession) RWC() io.ReadWriteCloser { return p.ptmx }

// Close releases the PTY file.
func (p *PTYSession) Close() {
	p.ptmx.Close() //nolint:errcheck
}

// Lifecycle implements the exec.Cmd-based Wait/Signal/Pid/PTY quartet
// shared by every POSIX sandbox backend box. Embed it by value in the
// backend's box struct and set Cmd (and Session, when running under a
// PTY) from Start; Wait/Signal/Pid/PTY then need no per-backend code.
type Lifecycle struct {
	Mu      sync.Mutex
	Cmd     *exec.Cmd
	Session *PTYSession
	Started bool
	Done    bool
}

// Wait blocks until Cmd exits and returns its exit code.
func (l *Lifecycle) Wait() (int, error) {
	if err := l.Cmd.Wait(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			l.Mu.Lock()
			l.Done = true
			l.Mu.Unlock()
			return exit.ExitCode(), nil
		}
		return 1, err
	}
	l.Mu.Lock()
	l.Done = true
	l.Mu.Unlock()
	return 0, nil
}

// Signal forwards sig to the running child, or no-ops if it never started
// or has already exited.
func (l *Lifecycle) Signal(sig os.Signal) error {
	l.Mu.Lock()
	defer l.Mu.Unlock()
	if l.Cmd == nil || l.Cmd.Process == nil {
		return nil
	}
	return l.Cmd.Process.Signal(sig)
}

// Pid returns the child process ID, or 0 if not started.
func (l *Lifecycle) Pid() int {
	l.Mu.Lock()
	defer l.Mu.Unlock()
	if l.Cmd == nil || l.Cmd.Process == nil {
		return 0
	}
	return l.Cmd.Process.Pid
}

// PTY returns the pseudo-terminal connected to the child, or nil when PTY
// mode is not active.
func (l *Lifecycle) PTY() io.ReadWriteCloser {
	if l.Session != nil {
		return l.Session.RWC()
	}
	return nil
}
