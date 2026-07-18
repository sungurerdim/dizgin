// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/sungurerdim/dizgin/internal/log"
)

// stdio owns three anonymous pipe pairs that bridge dizgin ↔ the
// restricted child for stdin/stdout/stderr.
//
// In the iter5 AppContainer backend the pipe SD had to grant the
// per-session AC SID (the child's identity at Low IL with an AC token)
// or its writes were silently dropped. In iter6 the child runs as the
// SAME user as dizgin (just with a restricted token at Medium IL), so the
// pipe SD only needs to grant the user SID. The kernel access check
// against the user SID succeeds for both parent and child.
//
// Layout (handle direction; arrow points writer → reader):
//
//	stdin:  parent.write (stdinW *os.File) → pipe → childRead  (stdinChild Handle)
//	stdout: childWrite  (stdoutChild)       → pipe → parent.read (stdoutR *os.File)
//	stderr: childWrite  (stderrChild)       → pipe → parent.read (stderrR *os.File)
type stdio struct {
	stdinChild  windows.Handle
	stdoutChild windows.Handle
	stderrChild windows.Handle

	stdinW  *os.File
	stdoutR *os.File
	stderrR *os.File

	// sdRetain holds the SECURITY_DESCRIPTOR backing the SECURITY_
	// ATTRIBUTES we hand to CreatePipe. The kernel copies the SD
	// internally on pipe creation so the value is technically safe
	// to free earlier, but the cost of holding it for the lifetime
	// of the box is a few hundred bytes and simplifies error paths.
	sdRetain *windows.SECURITY_DESCRIPTOR
}

// newStdio creates three user-SID-granted anonymous pipe pairs and
// returns a stdio struct the caller hands to Box.Start. Returns an
// error with all partial handles closed on failure.
func newStdio(trustee *windows.SID) (*stdio, error) {
	if trustee == nil {
		return nil, fmt.Errorf("restricted: stdio trustee is nil")
	}

	sd, err := buildUserGrantSD(trustee)
	if err != nil {
		return nil, fmt.Errorf("build pipe SD: %w", err)
	}

	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
		InheritHandle:      1,
	}

	s := &stdio{sdRetain: sd}

	// stdin: child reads, parent writes. Child end inheritable.
	var stdinR, stdinW windows.Handle
	if err := windows.CreatePipe(&stdinR, &stdinW, sa, 0); err != nil {
		return nil, fmt.Errorf("CreatePipe(stdin): %w", err)
	}
	if err := windows.SetHandleInformation(stdinW, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		_ = windows.CloseHandle(stdinR)
		_ = windows.CloseHandle(stdinW)
		return nil, fmt.Errorf("clear inherit on stdin parent: %w", err)
	}
	s.stdinChild = stdinR
	s.stdinW = os.NewFile(uintptr(stdinW), "restricted-stdin-w")

	// stdout: child writes, parent reads. Child end inheritable.
	var stdoutR, stdoutW windows.Handle
	if err := windows.CreatePipe(&stdoutR, &stdoutW, sa, 0); err != nil {
		s.closeAll()
		return nil, fmt.Errorf("CreatePipe(stdout): %w", err)
	}
	if err := windows.SetHandleInformation(stdoutR, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		_ = windows.CloseHandle(stdoutR)
		_ = windows.CloseHandle(stdoutW)
		s.closeAll()
		return nil, fmt.Errorf("clear inherit on stdout parent: %w", err)
	}
	s.stdoutChild = stdoutW
	s.stdoutR = os.NewFile(uintptr(stdoutR), "restricted-stdout-r")

	// stderr: child writes, parent reads. Child end inheritable.
	var stderrR, stderrW windows.Handle
	if err := windows.CreatePipe(&stderrR, &stderrW, sa, 0); err != nil {
		s.closeAll()
		return nil, fmt.Errorf("CreatePipe(stderr): %w", err)
	}
	if err := windows.SetHandleInformation(stderrR, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		_ = windows.CloseHandle(stderrR)
		_ = windows.CloseHandle(stderrW)
		s.closeAll()
		return nil, fmt.Errorf("clear inherit on stderr parent: %w", err)
	}
	s.stderrChild = stderrW
	s.stderrR = os.NewFile(uintptr(stderrR), "restricted-stderr-r")

	return s, nil
}

// closeChildEnds is called immediately after CreateProcessAsUserW
// succeeds. The child has duplicated each child-end handle through
// inheritance, so dizgin no longer needs its copies. Closing them lets the
// kernel maintain the correct reference count: when the child exits and
// closes its handles, the pipe write/read ends fully close and the
// parent's pump goroutine sees EOF.
func (s *stdio) closeChildEnds() {
	if s == nil {
		return
	}
	if s.stdinChild != 0 {
		_ = windows.CloseHandle(s.stdinChild)
		s.stdinChild = 0
	}
	if s.stdoutChild != 0 {
		_ = windows.CloseHandle(s.stdoutChild)
		s.stdoutChild = 0
	}
	if s.stderrChild != 0 {
		_ = windows.CloseHandle(s.stderrChild)
		s.stderrChild = 0
	}
}

// closeAll closes every handle the struct still owns. Safe to call
// multiple times — each close clears the field.
func (s *stdio) closeAll() {
	if s == nil {
		return
	}
	s.closeChildEnds()
	if s.stdinW != nil {
		_ = s.stdinW.Close()
		s.stdinW = nil
	}
	if s.stdoutR != nil {
		_ = s.stdoutR.Close()
		s.stdoutR = nil
	}
	if s.stderrR != nil {
		_ = s.stderrR.Close()
		s.stderrR = nil
	}
}

// startPumps wires the parent-side pipe ends to the supplied stdout
// and stderr writers. Pass os.Stdout / os.Stderr for the production
// path; the learn-mode pump passes an accessRecorder wrapping
// os.Stderr so denial lines are captured.
//
// Two output pumps register on wg so Wait() drains them before
// returning — without that, the tail of the tool's output races the
// dizgin process exit and gets truncated. The stdin pump is fire-and-
// forget; on a TTY-blocked Read it can outlive dizgin's exit, which is
// fine because the OS reaper catches the leaked goroutine.
//
// forwardStdin=false (typical --no-pty path) closes the parent end
// of the stdin pipe up front so the child sees EOF immediately. This
// avoids the long post-exit stall on Windows where a Go runtime exit
// cannot reclaim a goroutine blocked in kernel-level ReadFile(stdin)
// against an interactive console.
func (s *stdio) startPumps(wg *sync.WaitGroup, forwardStdin bool, stdoutDst, stderrDst io.Writer) {
	if s == nil {
		return
	}
	if stdoutDst == nil {
		stdoutDst = os.Stdout
	}
	if stderrDst == nil {
		stderrDst = os.Stderr
	}

	if s.stdinW != nil {
		if forwardStdin {
			go func(dst *os.File) {
				_, _ = io.Copy(dst, os.Stdin)
				_ = dst.Close()
			}(s.stdinW)
		} else {
			_ = s.stdinW.Close()
			s.stdinW = nil
		}
	}

	if s.stdoutR != nil {
		wg.Add(1)
		go func(src *os.File, dst io.Writer) {
			defer wg.Done()
			_, err := io.Copy(dst, src)
			if err != nil && !isClosedPipeErr(err) {
				log.DebugSub(log.SubContainer, "restricted: stdout pump: %v", err)
			}
		}(s.stdoutR, stdoutDst)
	}

	if s.stderrR != nil {
		wg.Add(1)
		go func(src *os.File, dst io.Writer) {
			defer wg.Done()
			_, err := io.Copy(dst, src)
			if err != nil && !isClosedPipeErr(err) {
				log.DebugSub(log.SubContainer, "restricted: stderr pump: %v", err)
			}
		}(s.stderrR, stderrDst)
	}
}

// buildUserGrantSD constructs a SECURITY_DESCRIPTOR whose DACL grants
// the supplied user SID GENERIC_ALL. Used as the security attributes
// for anonymous pipe creation so the child (running as the same user
// via the restricted token) is permitted by the kernel access check
// on the pipe handles inherited via STARTUPINFOEXW.
//
// Iter6 simplification vs the AppContainer model: only one SID is
// listed (user). The iter5 acStdio variant listed user + AC SID
// because the child token had the AC SID as its primary identity at
// Low IL — that identity is gone in iter6.
func buildUserGrantSD(trustee *windows.SID) (*windows.SECURITY_DESCRIPTOR, error) {
	if trustee == nil {
		return nil, fmt.Errorf("nil trustee SID")
	}
	sidStr := trustee.String()
	if sidStr == "" {
		return nil, fmt.Errorf("trustee SID is empty")
	}
	sddl := fmt.Sprintf("D:(A;;GA;;;%s)", sidStr)
	// Low-IL mode: append a Low integrity label (no-write-up) so the
	// Low-IL child may write its stdout/stderr into these pipes. Without
	// it the default Medium label would make the child's write a blocked
	// write-up and the tool would produce no output.
	if lowILEnabled() {
		sddl += "S:(ML;;NW;;;LW)"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("SDDL %q: %w", sddl, err)
	}
	return sd, nil
}

// isClosedPipeErr matches the assortment of "pipe is gone" error
// shapes that Windows surfaces when the other end of an anonymous
// pipe closes: ERROR_BROKEN_PIPE on read, ERROR_NO_DATA on write,
// "file already closed" when our own Close raced with the pump's
// Read.
func isClosedPipeErr(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_NO_DATA) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "file already closed") ||
		strings.Contains(s, "use of closed")
}
