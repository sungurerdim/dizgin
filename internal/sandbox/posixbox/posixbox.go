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
	"syscall"

	"github.com/creack/pty"

	"github.com/sungurerdim/dizgin/internal/platform"
)

// PTYSession holds the host-side PTY file for a sandboxed process.
type PTYSession struct {
	ptmx *os.File
}

// StartWithPTY starts cmd under a PTY and returns the host-side PTY file.
// The caller is responsible for closing the returned session.
//
// Unlike pty.Start(cmd), this puts the *slave* side in raw mode itself
// before the child ever runs, rather than trusting the sandboxed tool's own
// runtime to flip it in time. A freshly opened pty slave starts in the
// kernel's default cooked mode (ICANON+ECHO on); anything written into it
// during the window before the tool's TUI framework sets raw mode itself —
// including terminal capability query/responses dizgin transparently
// relays between the real host terminal and this pty (see cmd/dizgin's
// bridgePTY) — gets echoed straight back out by the line discipline
// instead of consumed as input. That produces garbled on-screen text and,
// because canonical mode line-buffers input until a newline, swallows
// single keypresses (e.g. a bare "1"/"2" at a y/n-style prompt) entirely.
// See platform.SetRaw's doc comment for the other half of this pairing.
func StartWithPTY(cmd *exec.Cmd) (*PTYSession, error) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		return nil, err
	}
	// Best-effort, matching how cmd/dizgin's own makeRaw call on the outer
	// terminal is already treated: proceed even on failure rather than
	// abort session startup over a raw-mode priming ioctl. The sandboxed
	// tool's own runtime remains the fallback, exactly as before this fix.
	_, _ = platform.SetRaw(tty)

	if cmd.Stdin == nil {
		cmd.Stdin = tty
	}
	if cmd.Stdout == nil {
		cmd.Stdout = tty
	}
	if cmd.Stderr == nil {
		cmd.Stderr = tty
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid = true
	cmd.SysProcAttr.Setctty = true

	if err := cmd.Start(); err != nil {
		tty.Close()  //nolint:errcheck
		ptmx.Close() //nolint:errcheck
		return nil, err
	}
	tty.Close() //nolint:errcheck // parent no longer needs the slave

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
//
// When the child was started via StartWithPTY (Session != nil), Setsid put
// it in its own new session/process group with pgid == pid, so the signal
// targets the whole group (syscall.Kill with a negative pid) rather than
// just the direct child. Without this, forwarding e.g. SIGTERM only ever
// reached the sandboxed tool's top-level process — any subprocess it
// spawned (an MCP server, a git/node child) kept running as an orphan,
// unlike native shell job control, where a signal to a foreground process
// group reaches every process in it. The plain (--no-pty) path never sets
// Setsid, so Session is nil there and this keeps signaling the single
// process as before.
func (l *Lifecycle) Signal(sig os.Signal) error {
	l.Mu.Lock()
	defer l.Mu.Unlock()
	if l.Cmd == nil || l.Cmd.Process == nil {
		return nil
	}
	if l.Session != nil {
		if sysSig, ok := sig.(syscall.Signal); ok {
			return syscall.Kill(-l.Cmd.Process.Pid, sysSig)
		}
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
