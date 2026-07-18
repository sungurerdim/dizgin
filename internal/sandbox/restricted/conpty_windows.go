// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"fmt"
	"io"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows ConPTY (pseudoconsole) support for the restricted backend.
//
// The pipe-based stdio path (stdio_windows.go) hands the child three
// anonymous pipes. A pipe is not a character device, so GetFileType
// returns FILE_TYPE_PIPE and isatty()==false inside the child — which
// drives interactive REPL tools (Claude Code's Bun runtime, aider, the
// node/python REPLs, etc.) into their non-interactive "--print" branch
// and breaks the native experience R2 promises.
//
// When dizgin's own stdin+stdout are real consoles (session.go computes
// opts.PTY from isTerminal), the backend instead allocates a Windows
// pseudoconsole via CreatePseudoConsole and attaches it to the child
// through PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE. The kernel then wires
// the child's stdio to the pseudoconsole's ConDrv endpoints, so the
// child sees a true character device (isatty==true) and runs in its
// native interactive mode. dizgin's existing terminal bridge
// (cmd/dizgin/pty.go bridgePTY) drives the host side unchanged — raw mode,
// resize forwarding (via the Resize method below), and the telemetry
// tee all work without intervention.

// procThreadAttributePseudoConsole is the PTAL attribute key that binds
// an HPCON to the child on CreateProcessAsUserW. Same encoding rule as
// the handle-list / mitigation attributes (see handle_list_windows.go):
// ProcThreadAttributePseudoConsole = 22, FALSE/TRUE/FALSE → 0x00020016.
const procThreadAttributePseudoConsole = 0x00020016

var (
	procCreatePseudoConsole = modKernel32.NewProc("CreatePseudoConsole")
	procResizePseudoConsole = modKernel32.NewProc("ResizePseudoConsole")
	procClosePseudoConsole  = modKernel32.NewProc("ClosePseudoConsole")
)

// packedCoord packs cols/rows into the single machine word the
// CreatePseudoConsole / ResizePseudoConsole ABI expects: COORD is a
// 4-byte struct (two SHORTs) passed by value, which the x64/arm64
// calling conventions hand over in one register as (Y<<16 | X).
func packedCoord(cols, rows uint16) uintptr {
	return uintptr(uint32(rows)<<16 | uint32(cols))
}

// conpty owns a pseudoconsole (HPCON) plus the dizgin-side pipe ends that
// drive it: dizgin writes keystrokes to inW and reads rendered VT output
// from outR. It implements io.ReadWriteCloser + Resize so dizgin's
// bridgePTY treats it like any other PTY master.
type conpty struct {
	hpc  windows.Handle // HPCON
	inW  *os.File       // dizgin → pseudoconsole (keystrokes)
	outR *os.File       // pseudoconsole → dizgin (rendered output)

	// inR / outW are the pseudoconsole-side pipe ends handed to
	// CreatePseudoConsole. They are deliberately kept open for the
	// session (NOT closed right after creation) — closing them before
	// the child spawns severs the wiring and the child never attaches.
	// closeConsole closes them after ClosePseudoConsole, which is also
	// what produces EOF on outR and unblocks dizgin's bridge read loop.
	inR  windows.Handle
	outW windows.Handle

	// tee, when non-nil, receives a copy of every chunk read out of the
	// pseudoconsole so the learn / auto-grant access recorder can scan
	// the merged stdout+stderr stream. bridgePTY renders the same bytes
	// to os.Stdout, so the recorder is constructed against io.Discard
	// (scan-only) to avoid double-printing the tool's output.
	tee io.Writer

	consoleOnce sync.Once
	pipeOnce    sync.Once
}

// newConPTY allocates a pseudoconsole sized to the host terminal. cols
// and rows fall back to the conventional 80×24 when the caller could
// not determine the host size.
//
// Pipe layout (arrow = writer → reader):
//
//	input:  dizgin (inW) → pipe → pseudoconsole (inR, handed to CreatePseudoConsole)
//	output: pseudoconsole (outW, handed to CreatePseudoConsole) → pipe → dizgin (outR)
//
// The pseudoconsole-side ends (inR / outW) are kept open for the
// lifetime of the session: closing them before CreateProcessAsUserW
// severs the wiring and the child fails to attach (it then falls back
// to the parent's inherited handles, breaking the TTY). They are closed
// in closeConsole, after ClosePseudoConsole.
func newConPTY(cols, rows uint16) (*conpty, error) {
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}

	var inR, inW windows.Handle
	if err := windows.CreatePipe(&inR, &inW, nil, 0); err != nil {
		return nil, fmt.Errorf("conpty: CreatePipe(input): %w", err)
	}
	var outR, outW windows.Handle
	if err := windows.CreatePipe(&outR, &outW, nil, 0); err != nil {
		_ = windows.CloseHandle(inR)
		_ = windows.CloseHandle(inW)
		return nil, fmt.Errorf("conpty: CreatePipe(output): %w", err)
	}

	var hpc windows.Handle
	r, _, _ := procCreatePseudoConsole.Call(
		packedCoord(cols, rows),
		uintptr(inR),
		uintptr(outW),
		0,
		uintptr(unsafe.Pointer(&hpc)),
	)
	if r != 0 { // HRESULT, S_OK == 0
		_ = windows.CloseHandle(inR)
		_ = windows.CloseHandle(inW)
		_ = windows.CloseHandle(outR)
		_ = windows.CloseHandle(outW)
		return nil, fmt.Errorf("conpty: CreatePseudoConsole: HRESULT=0x%08x", uint32(r))
	}

	return &conpty{
		hpc:  hpc,
		inW:  os.NewFile(uintptr(inW), "conpty-in-w"),
		outR: os.NewFile(uintptr(outR), "conpty-out-r"),
		inR:  inR,
		outW: outW,
	}, nil
}

// Read pulls rendered output from the pseudoconsole. When a tee is
// installed, each chunk is mirrored to it (best-effort) so the access
// recorder can scan the stream for denial lines.
func (c *conpty) Read(p []byte) (int, error) {
	n, err := c.outR.Read(p)
	if n > 0 && c.tee != nil {
		_, _ = c.tee.Write(p[:n])
	}
	return n, err
}

// Write forwards host keystrokes to the pseudoconsole input.
func (c *conpty) Write(p []byte) (int, error) {
	return c.inW.Write(p)
}

// Resize forwards a host terminal resize to the pseudoconsole so TUI
// tools reflow. Implements cmd/dizgin.PTYResizer; bridgePTY detects it at
// runtime and wires watchResize to it.
func (c *conpty) Resize(width, height uint16) error {
	if c.hpc == 0 {
		return nil
	}
	r, _, _ := procResizePseudoConsole.Call(uintptr(c.hpc), packedCoord(width, height))
	if r != 0 {
		return fmt.Errorf("conpty: ResizePseudoConsole: HRESULT=0x%08x", uint32(r))
	}
	return nil
}

// closeConsole tears down the pseudoconsole. ClosePseudoConsole signals
// conhost to flush any pending output and close its end of the output
// pipe, which surfaces as EOF on outR — that EOF is what unblocks dizgin's
// bridgePTY read loop. Idempotent: safe from both the exit reaper and
// the bridge's deferred Close.
func (c *conpty) closeConsole() {
	c.consoleOnce.Do(func() {
		if c.hpc != 0 {
			_, _, _ = procClosePseudoConsole.Call(uintptr(c.hpc))
			c.hpc = 0
		}
		// Close the pseudoconsole-side pipe ends only after the console
		// itself is torn down. Dropping our copy of the output write end
		// here is what leaves the output pipe with no writers, surfacing
		// EOF on outR so dizgin's bridge read loop unblocks.
		if c.inR != 0 {
			_ = windows.CloseHandle(c.inR)
			c.inR = 0
		}
		if c.outW != 0 {
			_ = windows.CloseHandle(c.outW)
			c.outW = 0
		}
	})
}

// Close releases the pseudoconsole and the dizgin-side pipe ends. Called
// by bridgePTY on exit and again by box.Cleanup; both paths are
// idempotent.
func (c *conpty) Close() error {
	if c == nil {
		return nil
	}
	c.closeConsole()
	c.pipeOnce.Do(func() {
		if c.inW != nil {
			_ = c.inW.Close()
		}
		if c.outR != nil {
			_ = c.outR.Close()
		}
	})
	return nil
}

// applyPseudoConsolePTAL registers a PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
// entry on the supplied PTAL so the child's stdio is wired to hpc on
// spawn. The HPCON value must remain addressable until
// CreateProcessAsUserW returns; the box holds the conpty (and thus hpc)
// alive across the spawn.
func applyPseudoConsolePTAL(listPtr unsafe.Pointer, hpc windows.Handle) error {
	if hpc == 0 {
		return fmt.Errorf("conpty: nil HPCON")
	}
	if r, _, e := procUpdateProcThreadAttribute.Call(
		uintptr(listPtr),
		0,
		uintptr(procThreadAttributePseudoConsole),
		uintptr(hpc),
		unsafe.Sizeof(hpc),
		0,
		0,
	); r == 0 {
		return fmt.Errorf("UpdateProcThreadAttribute(PSEUDOCONSOLE): %w", e)
	}
	return nil
}
