// SPDX-License-Identifier: MIT

//go:build windows

package main

import (
	"context"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// isTerminal reports whether f is a Windows console.
func isTerminal(f *os.File) bool {
	var mode uint32
	err := windows.GetConsoleMode(windows.Handle(f.Fd()), &mode)
	return err == nil
}

// makeRaw sets the Windows console to raw input/VT-output mode.
// Returns a restore function and any error.
func makeRaw(in, out *os.File) (restore func(), err error) {
	inHandle := windows.Handle(in.Fd())
	outHandle := windows.Handle(out.Fd())

	var inMode, outMode uint32
	if err = windows.GetConsoleMode(inHandle, &inMode); err != nil {
		return nil, err
	}
	if err = windows.GetConsoleMode(outHandle, &outMode); err != nil {
		return nil, err
	}

	// Raw input: remove echo, line buffering, processed input.
	// Enable virtual terminal input so xterm mouse sequences, focus events, and
	// bracketed paste reach the TUI tool as VT escape sequences.
	// Quick Edit Mode is intentionally preserved: it allows the user to select
	// and copy text in the console window while the tool is running.
	rawIn := inMode &^ (windows.ENABLE_ECHO_INPUT |
		windows.ENABLE_LINE_INPUT |
		windows.ENABLE_PROCESSED_INPUT)
	rawIn |= windows.ENABLE_VIRTUAL_TERMINAL_INPUT

	// Output: enable VT processing.
	rawOut := outMode | windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING

	if err = windows.SetConsoleMode(inHandle, rawIn); err != nil {
		return nil, err
	}
	if err = windows.SetConsoleMode(outHandle, rawOut); err != nil {
		windows.SetConsoleMode(inHandle, inMode) //nolint:errcheck
		return nil, err
	}

	restore = func() {
		windows.SetConsoleMode(inHandle, inMode)   //nolint:errcheck
		windows.SetConsoleMode(outHandle, outMode) //nolint:errcheck
	}
	return restore, nil
}

// currentTerminalSize returns the current host console window dimensions.
// Returns (0, 0, false) if the size cannot be determined.
func currentTerminalSize() (uint16, uint16, bool) {
	outHandle := windows.Handle(os.Stdout.Fd())
	var info windows.ConsoleScreenBufferInfo
	if err := windows.GetConsoleScreenBufferInfo(outHandle, &info); err != nil {
		return 0, 0, false
	}
	w := uint16(info.Window.Right - info.Window.Left + 1)
	h := uint16(info.Window.Bottom - info.Window.Top + 1)
	return w, h, w > 0 && h > 0
}

// watchResize polls the host console window size every 100 ms and calls fn
// whenever the dimensions change. Stops when ctx is cancelled.
// Windows does not deliver a SIGWINCH-equivalent signal, so polling is the
// only reliable mechanism for detecting terminal resize events.
func watchResize(ctx context.Context, fn func(w, h uint16)) {
	outHandle := windows.Handle(os.Stdout.Fd())

	getSize := func() (uint16, uint16, bool) {
		var info windows.ConsoleScreenBufferInfo
		if err := windows.GetConsoleScreenBufferInfo(outHandle, &info); err != nil {
			return 0, 0, false
		}
		w := uint16(info.Window.Right - info.Window.Left + 1)
		h := uint16(info.Window.Bottom - info.Window.Top + 1)
		return w, h, true
	}

	prevW, prevH, _ := getSize()

	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w, h, ok := getSize()
			if ok && (w != prevW || h != prevH) {
				prevW, prevH = w, h
				fn(w, h)
			}
		}
	}
}
