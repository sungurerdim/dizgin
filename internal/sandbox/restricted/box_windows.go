// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"context"
	"fmt"
	"io"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/log"
)

// CreateProcess flags + constants x/sys/windows does not export.
const (
	extendedStartupinfoPresent = 0x00080000 // EXTENDED_STARTUPINFO_PRESENT
	createUnicodeEnvironment   = 0x00000400 // CREATE_UNICODE_ENVIRONMENT
)

// startupinfoExW mirrors STARTUPINFOEXW from processthreadsapi.h.
type startupinfoExW struct {
	StartupInfo   windows.StartupInfo
	AttributeList unsafe.Pointer
}

// PTAL syscalls. UpdateProcThreadAttribute is declared in
// handle_list_windows.go; the other two pair with it for list setup
// and teardown.
var (
	procInitializeProcThreadAttributeList = modKernel32.NewProc("InitializeProcThreadAttributeList")
	procDeleteProcThreadAttributeList     = modKernel32.NewProc("DeleteProcThreadAttributeList")
	procCreateProcessAsUserW              = modAdvapi32.NewProc("CreateProcessAsUserW")
)

// handleListAllowlistEnabled mirrors the AppContainer helper of the
// same name. Precedence (highest first):
//
//  1. DIZGIN_NO_HANDLE_LIST=1 — runtime emergency switch.
//  2. CreateOpts.HandleListAllowlist (per-profile flag).
//  3. Default ON.
func (b *box) handleListAllowlistEnabled() bool {
	if os.Getenv(brand.Env("NO_HANDLE_LIST")) == "1" {
		return false
	}
	if b.opts.HandleListAllowlist != nil {
		return *b.opts.HandleListAllowlist
	}
	return true
}

// procThreadAttributeListEntriesCount returns the slot count the
// PROC_THREAD_ATTRIBUTE_LIST must allocate. The restricted backend
// always uses 1 slot for the mitigation policy; +1 for either the
// pseudoconsole (PTY mode) or the HANDLE_LIST allowlist (pipe mode).
//
// PTY mode and the handle-list allowlist are mutually exclusive: a
// pseudoconsole child does not inherit the stdio pipe handles (the
// kernel wires its stdio to the ConDrv endpoints), and the spawn runs
// with bInheritHandles=FALSE, so there is no inheritable-handle set to
// scope.
//
// Note: SECURITY_CAPABILITIES (the AppContainer slot) is NOT used —
// the restricted token does not need a capability set.
func (b *box) procThreadAttributeListEntriesCount() uint32 {
	if b.usePTY {
		return 2 // mitigation + pseudoconsole
	}
	if b.handleListAllowlistEnabled() {
		return 2 // mitigation + handle list
	}
	return 1
}

// Start launches cmd inside the restricted box: builds the Medium-IL
// restricted token, the PTAL with mitigation + optional handle-list
// allowlist, the STARTUPINFOEXW with owned stdio pipes whose SD
// grants the user SID, and finally calls CreateProcessAsUserW.
//
// On any error before the spawn, every allocated handle is closed
// before returning so dizgin's exit path does not leak file descriptors.
func (b *box) Start(_ context.Context, cmd string, args []string, env []string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.started {
		return fmt.Errorf("restricted: already started")
	}

	// Integrity level: Medium by default; Low when the experimental R3
	// write-scoping switch (DIZGIN_LOW_IL=1) is set. At Low IL the child
	// can read Medium objects but not write/delete them; the writable set
	// (scratch, stdio/ConPTY pipes, and — Phase B — workdir/tool dirs) is
	// relabelled Low so the child can write exactly there.
	token, err := CreateRestrictedTokenForLevel(lowILTokenLevel())
	if err != nil {
		return fmt.Errorf("restricted: create token: %w", err)
	}
	defer func() { _ = token.Close() }()

	// Allocate the pseudoconsole first when running in PTY mode — its
	// HPCON is needed both for the PTAL slot count and the
	// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE entry that setupStdio adds.
	// On any spawn failure below, Cleanup closes it.
	if b.usePTY {
		cp, cpErr := newConPTY(b.opts.InitialCols, b.opts.InitialRows)
		if cpErr != nil {
			return fmt.Errorf("restricted: %w", cpErr)
		}
		b.conpty = cp
	}

	// Low-IL write-scoping: relabel the writable set (workdir +
	// declared-RW mounts) Low so the Low-IL child can write there while
	// every other Medium object stays read-only to it. Best-effort per
	// path; reverted in Cleanup.
	if lowILEnabled() {
		b.applyLowLabels()
	}

	// listBuf must stay alive through the spawn (held as a local +
	// KeepAlive in spawnProcess); the delete defer lives here so it
	// fires last.
	listBuf, listPtr, flagsPtr, err := b.setupPTAL()
	if err != nil {
		return err
	}
	defer func() { _, _, _ = procDeleteProcThreadAttributeList.Call(uintptr(listPtr)) }()

	stdioPipes, si, allowedHandles, err := b.setupStdio(listPtr)
	if err != nil {
		return err
	}

	pCmdLine, pWorkdir, envBlock, err := buildProcArgs(b.opts.Workdir, cmd, args, env)
	if err != nil {
		stdioPipes.closeAll()
		return err
	}

	// The syscall + its KeepAlive guards are co-located in spawnProcess.
	// PTY mode spawns with bInheritHandles=FALSE (the child reaches its
	// pseudoconsole via the PTAL, not inheritance); pipe mode inherits
	// the stdio handles scoped by the handle-list allowlist.
	pi, err := spawnProcess(token, &si, pCmdLine, pWorkdir, envBlock, allowedHandles, flagsPtr, listBuf, !b.usePTY)
	if err != nil {
		stdioPipes.closeAll()
		return err
	}
	stdioPipes.closeChildEnds()

	job, err := b.attachJob(pi)
	if err != nil {
		stdioPipes.closeAll()
		return err
	}

	b.finalizeStart(pi, job, stdioPipes)
	return nil
}

// finalizeStart records the spawned process handles on the box and wires
// the output pumps. Network allowlist enforcement is NOT done here — it
// is brokered by dizgin (cmd/dizgin) through the elevated dizgind daemon
// (internal/netfilter); the box never holds FWPM_ACTRL_ADD.
func (b *box) finalizeStart(pi windows.ProcessInformation, job windows.Handle, stdioPipes *stdio) {
	b.procH = pi.Process
	b.threadH = pi.Thread
	b.jobH = job
	b.pid = pi.ProcessId
	b.started = true
	b.stdio = stdioPipes

	if b.conpty != nil {
		// PTY mode: the child's stdout+stderr are merged into the
		// pseudoconsole stream, which dizgin's bridgePTY renders. There are
		// no stdio pipe pumps. Wire the learn / auto-grant recorder as a
		// scan-only tee on the pseudoconsole output — bridgePTY already
		// renders the bytes to os.Stdout, so the recorder forwards to
		// io.Discard (target) to avoid double-printing the tool output.
		if b.opts.LearnMode || autoGrantEnabled() {
			b.recorder = newAccessRecorder(io.Discard)
			b.conpty.tee = b.recorder
		}
		// Reap the child off-thread and close the pseudoconsole on exit
		// so dizgin's bridge read loop unblocks: ConPTY keeps its output
		// pipe open across child exit until ClosePseudoConsole. The
		// captured *conpty (not b.conpty) keeps this goroutine race-free
		// against Cleanup niling the field; closeConsole is idempotent.
		go b.reapConsoleOnExit(pi.Process, b.conpty)
		log.DebugSub(log.SubContainer, "restricted: started pid=%d sid=%s session=%s pty=conpty learn=%v",
			pi.ProcessId, b.userSID.String(), b.sessionID, b.opts.LearnMode)
		return
	}

	// Wrap stderr with an access-denial recorder so the post-session flow
	// can react to denied paths. Created for explicit --learn (interactive
	// review) AND for the zero-config auto-grant path (Phase 4c), unless
	// auto-grant is disabled via DIZGIN_NO_AUTO_GRANT=1. The recorder
	// forwards every byte to os.Stderr in real time — terminal output is
	// unaffected.
	var stderrDst io.Writer = os.Stderr
	if b.opts.LearnMode || autoGrantEnabled() {
		b.recorder = newAccessRecorder(os.Stderr)
		stderrDst = b.recorder
	}
	stdioPipes.startPumps(&b.stdioPumps, b.usePTY, os.Stdout, stderrDst)

	log.DebugSub(log.SubContainer, "restricted: started pid=%d sid=%s session=%s learn=%v",
		pi.ProcessId, b.userSID.String(), b.sessionID, b.opts.LearnMode)
}
