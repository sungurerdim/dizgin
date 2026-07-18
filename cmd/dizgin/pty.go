// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/sungurerdim/dizgin/internal/log"
)

// PTYResizer is optionally implemented by PTY objects that support forwarding
// terminal resize events. bridgePTY detects the interface at runtime and starts
// a platform-specific goroutine (watchResize) that polls or signals for size changes.
type PTYResizer interface {
	Resize(width, height uint16) error
}

// bridgePTY copies between the PTY and the host terminal until the PTY closes.
//
// When observers is non-empty, every byte coming out of the PTY (tool's
// combined stdout/stderr) is tee'd to each observer in addition to the host
// terminal. This is how the access telemetry catches "file not found"
// messages without needing a separate stderr channel, which PTY mode
// collapses into a single stream anyway.
func bridgePTY(pty io.ReadWriteCloser, observers ...io.Writer) error {
	// Save window title so it can be restored after the tool changes it.
	// \e[22t pushes the current title onto the terminal's stack.
	os.Stdout.WriteString("\x1b[22t")       //nolint:errcheck
	defer os.Stdout.WriteString("\x1b[23t") //nolint:errcheck // pop title back

	// Terminal cleanup runs on every exit path — normal completion, PTY
	// close, Ctrl+C, errored copy. Placing it in a defer is cheap and
	// guarantees the terminal returns to a usable state even when the tool
	// crashes mid-frame or the user interrupts while alternate-screen is
	// active. Idempotent: safe to call multiple times.
	defer resetHostTerminal()

	// Set host terminal to raw mode so keypresses go straight to the tool.
	restore, err := makeRaw(os.Stdin, os.Stdout)
	if err == nil && restore != nil {
		defer restore()
	}

	// If the PTY supports resize, forward host terminal resize events to the
	// container's ConPTY so TUI tools (Claude Code, Aider, etc.) can reflow.
	if resizer, ok := pty.(PTYResizer); ok {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		// Send the current terminal size immediately so the container ConPTY
		// starts at the right dimensions. watchResize only fires on changes,
		// so without this initial push the container defaults to 80×24.
		if w, h, ok2 := currentTerminalSize(); ok2 {
			resizer.Resize(w, h) //nolint:errcheck
		}
		go watchResize(ctx, func(w, h uint16) {
			resizer.Resize(w, h) //nolint:errcheck
		})
	}

	done := make(chan error, 1)

	// PTY → stdout (+ optional observers for telemetry tee).
	sink := io.Writer(os.Stdout)
	if len(observers) > 0 {
		writers := make([]io.Writer, 0, 1+len(observers))
		writers = append(writers, os.Stdout)
		for _, o := range observers {
			if o != nil {
				writers = append(writers, o)
			}
		}
		sink = io.MultiWriter(writers...)
	}
	go func() {
		_, copyErr := io.Copy(sink, pty)
		done <- copyErr
	}()

	// stdin → PTY (closing PTY on exit unblocks the read goroutine above)
	go func() {
		io.Copy(pty, os.Stdin) //nolint:errcheck
		// stdin closed or errored — close PTY write side to signal EOF.
		pty.Close() //nolint:errcheck
	}()

	err = <-done
	// Close PTY to unblock stdin→PTY goroutine if it's still blocked on stdin.Read.
	pty.Close() //nolint:errcheck

	return err
}

// terminalResetOnce ensures the escape-sequence cleanup runs at most once
// per session. The defer chain in bridgePTY and the Ctrl+C fast path in
// cleanup_windows.go may both reach resetHostTerminal; duplicate sequences
// are harmless but a second \r\n after a clean exit leaves a visual blank
// line in the shell prompt below dizgin.
var terminalResetOnce sync.Once

// resetHostTerminal restores the host terminal to a known-good state after
// the tool inside the container exits.
//
// The problem: TUI tools (Claude Code, Aider) push the terminal into the
// alternate screen buffer, enable raw mode + bracketed paste + mouse
// reporting, and may set a DECSTBM scrolling region that does not cover
// the full viewport. On a normal exit the tool cleans up, but on Ctrl+C,
// crash, or container signal the escape sequences never fire. The shell
// prompt afterwards lands in an undefined state — symptoms the user
// reported: cursor jumps to the top, new lines overwrite old content,
// autowrap off, scrolling region wrong.
//
// The fix sends a conservative ordered cleanup: exit alternate screen,
// reset scrolling region, text attributes, cursor shape, mouse + paste
// modes; re-enable autowrap; then ERASE the visible screen and park the
// cursor at (1,1). The erase is the piece that was missing before —
// exiting alternate-screen in ConPTY / Windows Terminal leaves whatever
// remained of the tool's last frame on the normal buffer, and the
// cursor at (1,1) then overwrote the old content one line at a time.
//
// The scrollback buffer is intentionally NOT touched (\x1b[3J would
// wipe it): the user can still scroll up to inspect the tool's output.
// Only the visible viewport is cleared so the next shell prompt starts
// on a blank canvas.
//
// Every sequence is idempotent: running this twice is a no-op beyond a
// redundant clear, which still leaves the terminal in the desired state.
func resetHostTerminal() {
	terminalResetOnce.Do(func() {
		seqs := []string{
			"\x1b[?1049l", // exit alternate screen buffer
			"\x1b[?1047l", // alternate screen buffer fallback clear (older terms)
			"\x1b[?47l",   // oldest alternate-screen alias — paranoia
			"\x1b[r",      // DECSTBM — reset scrolling region to full screen
			"\x1b[?7h",    // DECAWM — re-enable autowrap
			"\x1b[0m",     // SGR reset: clear color/bold/underline/reverse
			"\x1b[0 q",    // DECSCUSR — default cursor shape (blinking block)
			"\x1b[?25h",   // DECTCEM — ensure cursor is visible
			"\x1b[?9l",    // disable X10 mouse (legacy)
			"\x1b[?1000l", // disable mouse tracking (normal)
			"\x1b[?1002l", // disable button-event tracking
			"\x1b[?1003l", // disable all-motion tracking
			"\x1b[?1004l", // disable focus reporting
			"\x1b[?1006l", // disable SGR mouse encoding
			"\x1b[?1015l", // disable URXVT mouse encoding
			"\x1b[?1016l", // disable SGR pixel mouse
			"\x1b[?2004l", // disable bracketed paste
			"\x1b[H",      // cursor to home (row 1, column 1)
			"\x1b[2J",     // erase the entire visible screen (scrollback kept)
			"\x1b[H",      // cursor to home again — some terminals move cursor on \x1b[2J
		}
		for _, s := range seqs {
			if _, err := os.Stdout.WriteString(s); err != nil {
				log.Debug("resetHostTerminal: write terminal sequence failed: %v", err)
				break
			}
		}
	})
}

func isClosedPipeError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "file already closed") ||
		strings.Contains(s, "use of closed")
}
