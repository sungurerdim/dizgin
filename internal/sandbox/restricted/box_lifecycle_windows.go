// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/sungurerdim/dizgin/internal/audit"
	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/log"
	"github.com/sungurerdim/dizgin/internal/sandbox"
	"github.com/sungurerdim/dizgin/internal/security"
)

// procGenerateConsoleCtrlEvent is used by Signal to attempt a graceful
// CTRL_BREAK delivery before falling back to TerminateProcess.
var procGenerateConsoleCtrlEvent = modKernel32.NewProc("GenerateConsoleCtrlEvent")

// box implements sandbox.Box for the iter6 restricted backend. State
// is guarded by mu so Wait/Signal/Cleanup can run from different
// goroutines (dizgin's exit handler does all three).
type box struct {
	ctx       context.Context
	opts      sandbox.CreateOpts
	sessionID string

	// userSID is the trustee for every session-scoped DACL stamp and
	// the SID granted GENERIC_ALL on each stdio pipe SD. Cleanup
	// uses it as the revoke trustee for the DENY-ACE list.
	userSID *windows.SID

	// deniedPaths is the list of paths where StampPathDeny succeeded
	// at session start. Cleanup feeds it into revokeStampsParallel
	// to undo every applied DENY before dizgin exits.
	deniedPaths []string

	scratchDir string

	// lowLabeled holds the writable-set paths (workdir + declared-RW
	// mounts) that were relabelled Low for an DIZGIN_LOW_IL session, so
	// Cleanup can revert them to Medium.
	lowLabeled []string

	// selfACEPaths holds the writable-set paths where applyLowLabels had
	// to add a temporary non-inheriting Full-Control ACE for userSID
	// before the Low relabel could succeed (the user owns the path but no
	// existing ACE granted WRITE_OWNER — common for dirs under a foreign-
	// owned parent like D:\GitHub). Cleanup revokes the ACE AFTER reverting
	// the Low label (the revert itself needs the WRITE_OWNER the ACE grants).
	selfACEPaths []string

	policies  Policies
	jobLimits JobLimits
	usePTY    bool

	mu       sync.Mutex
	started  bool
	done     bool
	procH    windows.Handle
	threadH  windows.Handle
	jobH     windows.Handle
	pid      uint32
	exitCode uint32

	stdio      *stdio
	stdioPumps sync.WaitGroup

	// conpty is non-nil when usePTY is set: the child is attached to a
	// Windows pseudoconsole instead of the three anonymous stdio pipes,
	// so interactive REPL tools see a real character device. PTY()
	// surfaces it to dizgin's terminal bridge. See conpty_windows.go.
	conpty *conpty

	// recorder is the iter6 Phase 5 access-denial scanner. Non-nil
	// when opts.LearnMode is true; box.Wait flushes + summarises it
	// after the child exits.
	recorder *accessRecorder
}

// reapConsoleOnExit blocks until the sandboxed child exits, then closes
// the pseudoconsole so conhost flushes its tail and closes the output
// pipe — the resulting EOF on the dizgin-side read end is what unblocks
// dizgin's bridgePTY copy loop. Operates on the captured *conpty only (no
// box fields) so it cannot race Cleanup. box.Wait re-waits the same
// process handle afterwards; a signaled handle stays signaled, so the
// exit-code read is unaffected.
//
// Handle-lifetime contract: proc is the duplicated process handle from
// ProcessInformation. It remains valid for the lifetime of this
// goroutine because Cleanup does not close procH until after Wait
// returns — and Wait only returns after stdioPumps (or this goroutine
// for the ConPTY path) complete. The Job Object timeout (resources.timeout,
// default 30 m) is what bounds INFINITE waits in practice: the Job
// terminates the child and proc becomes signalled at that point.
func (b *box) reapConsoleOnExit(proc windows.Handle, cp *conpty) {
	// WaitForSingleObject(INFINITE): bounded in practice by the Job Object
	// timeout (resources.timeout, default 30 m). The handle stays valid
	// because Cleanup holds off closing procH until after this goroutine
	// unblocks Wait (see handle-lifetime contract in the doc comment above).
	_, _ = windows.WaitForSingleObject(proc, windows.INFINITE)
	cp.closeConsole()
}

// Wait blocks until the child exits and returns the exit code. The
// output pumps started in Start are drained before returning so
// callers see the full stdout/stderr tail.
func (b *box) Wait() (int, error) {
	b.mu.Lock()
	if !b.started {
		b.mu.Unlock()
		return 1, fmt.Errorf("restricted: not started")
	}
	proc := b.procH
	b.mu.Unlock()

	// WaitForSingleObject(INFINITE): bounded in practice by the Job Object
	// timeout (resources.timeout, default 30 m). The handle stays valid
	// for this call because Cleanup holds off closing procH until after
	// Wait returns (dizgin's exit handler calls Wait before Cleanup).
	if _, err := windows.WaitForSingleObject(proc, windows.INFINITE); err != nil {
		return 1, fmt.Errorf("restricted: WaitForSingleObject: %w", err)
	}
	var code uint32
	if err := windows.GetExitCodeProcess(proc, &code); err != nil {
		return 1, fmt.Errorf("restricted: GetExitCodeProcess: %w", err)
	}
	b.stdioPumps.Wait()

	// Phase 5 learn mode: flush any partial tail then print the
	// post-session summary. PrintLearnSummary lands on os.Stderr
	// BEFORE box.Cleanup tears down handles so the diagnostic survives
	// a Ctrl+C path through dizgin's exit handler.
	if b.recorder != nil {
		b.recorder.flushPartial()
		if b.opts.LearnMode {
			PrintLearnSummary(os.Stderr, b.recorder.Hits())
			b.maybePromptAndSavePermissions()
		} else {
			// Zero-config (Phase 4c): auto-grant RO for non-sensitive
			// denials, never touch the sensitive SSOT automatically.
			b.maybeAutoGrantPermissions()
		}
	}

	b.mu.Lock()
	b.exitCode = code
	b.done = true
	b.mu.Unlock()
	return int(code), nil
}

// Signal forwards an OS signal to the sandboxed process tree.
//
// Windows signal mapping:
//   - os.Interrupt / syscall.SIGINT: attempt a graceful CTRL_BREAK_EVENT
//     via GenerateConsoleCtrlEvent. This only works when the child shares
//     a console (ConPTY path: the pseudoconsole host has its own console
//     that is NOT the same as dizgin's, so the event cannot cross the
//     session boundary; pipe path: anonymous pipes carry no console
//     context). In both cases GenerateConsoleCtrlEvent will fail with
//     ERROR_INVALID_PARAMETER or ERROR_ACCESS_DENIED, and the fallback
//     is TerminateProcess. The attempt is made anyway so that future
//     configurations where a shared console IS present (e.g. a test
//     harness that attaches to the same conhost) receive graceful
//     termination without a code change.
//   - os.Kill / syscall.SIGKILL / any other signal: TerminateProcess
//     immediately. Windows has no portable graceful kill path outside of
//     a shared console; the Job Object's kill-on-close catches any
//     stragglers when Cleanup runs.
//
// The sig argument is never silently discarded: the mapping above is
// explicit for every case, matching the contract that seatbelt and
// bubblewrap backends satisfy via cmd.Process.Signal(sig).
func (b *box) Signal(sig os.Signal) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.started || b.done || b.procH == 0 {
		return nil
	}
	if sig == os.Interrupt {
		// Attempt graceful CTRL_BREAK. GenerateConsoleCtrlEvent targets
		// the process group (pid); if the child has no console attachment
		// the call fails and we fall through to TerminateProcess.
		r, _, _ := procGenerateConsoleCtrlEvent.Call(
			uintptr(windows.CTRL_BREAK_EVENT),
			uintptr(b.pid),
		)
		if r != 0 {
			return nil
		}
		// Fall through: no console attachment or not in the same group.
	}
	return windows.TerminateProcess(b.procH, 1)
}

// Pid returns the child process ID for the monitor / suspend path.
func (b *box) Pid() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return int(b.pid)
}

// JobHandle returns the Job Object handle so monitor code can pull
// resource counters via QueryInformationJobObject.
func (b *box) JobHandle() uintptr {
	b.mu.Lock()
	defer b.mu.Unlock()
	return uintptr(b.jobH)
}

// TempDir returns the per-session scratch directory.
func (b *box) TempDir() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.scratchDir
}

// PTY returns the pseudoconsole master when the session runs in PTY
// mode (dizgin's stdin+stdout are real consoles), or nil for the pipe path
// (--no-pty, CI, redirected stdio). dizgin's bridgePTY (cmd/dizgin/pty.go)
// detects the non-nil value and drives raw-mode + resize + the
// telemetry tee on the host side.
//
// Returns an untyped nil when there is no pseudoconsole so the caller's
// `pty != nil` guard is correct (a typed nil *conpty would read as a
// non-nil interface).
func (b *box) PTY() io.ReadWriteCloser {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conpty == nil {
		return nil
	}
	return b.conpty
}

// applyLowLabels relabels the session's writable set Low so the Low-IL
// child can write there. The set is the workdir plus every declared-RW
// mount (config_dirs, mcp_dirs, tool_deps read_write). Read-only and
// system mounts are left Medium — the child reads them via read-up.
//
// Two correctness guards distinguish the workdir from declared-RW mounts:
//
//   - declared-RW mounts run through security.IsIntegrityDenied, which
//     refuses volume roots, system/tool/PATH denylist dirs, and any dir
//     that contains executables. This stops dizgin from trying to lower the
//     integrity of e.g. C:\Program Files\Git (it would always fail, and
//     if it ever succeeded a Low process could replace those binaries).
//   - the workdir is the user's explicit project — it may legitimately
//     contain build outputs / scripts, so it is exempt from the
//     executable scan; only volume-root / system-path are refused. A
//     workdir that cannot be made writable is surfaced as a visible
//     warning (previously this failure was silent — the tool would then
//     be unable to write the project with no diagnostic).
//
// Relabel uses lowLabelWritable, which adds a temporary self-ACE when the
// user owns the path but lacks WRITE_OWNER (see that method). Best-effort
// per path: a non-workdir failure is logged but does not abort the session.
func (b *box) applyLowLabels() {
	seen := make(map[string]bool)
	mark := func(p string) bool {
		if p == "" || seen[p] {
			return false
		}
		seen[p] = true
		return true
	}

	// Workdir (and any CategoryWorkdir mount): relabel, warn loudly on
	// failure since the child cannot function without a writable workdir.
	labelWorkdir := func(p string) {
		if !mark(p) {
			return
		}
		if security.IsVolumeRoot(p) || security.IsSystemPath(p) {
			log.DebugSub(log.SubContainer, "restricted: refuse low-label workdir %s (volume root / system path)", p)
			fmt.Fprintf(os.Stderr, brand.Name+": warning: workdir %s cannot be made writable at Low IL (volume root or system path); the tool may be unable to write here\n", p)
			return
		}
		if !b.lowLabelWritable(p) {
			fmt.Fprintf(os.Stderr, brand.Name+": warning: could not lower integrity of workdir %s; a Low-IL tool may be unable to write here (set DIZGIN_LOW_IL=0 to disable Low-IL mode)\n", p)
		}
	}

	// Declared-RW mount: relabel only when IsIntegrityDenied clears it.
	labelRW := func(p string) {
		if !mark(p) {
			return
		}
		if denied, reason := security.IsIntegrityDenied(p); denied {
			log.DebugSub(log.SubContainer, "restricted: skip low-label %s (%s)", p, reason)
			return
		}
		_ = b.lowLabelWritable(p)
	}

	labelWorkdir(b.opts.Workdir)
	for _, m := range b.opts.Mounts {
		switch m.Category {
		case sandbox.CategoryWorkdir:
			labelWorkdir(m.Host)
		case sandbox.CategoryDeclaredRW:
			if m.ReadOnly {
				continue
			}
			labelRW(m.Host)
		}
	}
	log.DebugSub(log.SubContainer, "restricted: low-labelled %d writable paths (%d via self-ACE)",
		len(b.lowLabeled), len(b.selfACEPaths))
}

// lowLabelWritable relabels dir Low and records it for revert. On the
// first attempt's ACCESS_DENIED it retries once after granting userSID a
// temporary non-inheriting Full-Control ACE — valid only when dizgin owns
// dir, because an owner holds implicit WRITE_DAC (so the grant succeeds)
// but NOT implicit WRITE_OWNER (which setting the mandatory label needs).
// Dirs under a foreign-owned parent (e.g. D:\GitHub) inherit only
// Modify/Read ACEs for the current user and hit exactly this case.
//
// Returns true when dir ended up Low-labelled. Paths that needed the
// self-ACE are tracked in selfACEPaths so Cleanup revokes the ACE after
// reverting the label (the revert also needs WRITE_OWNER).
func (b *box) lowLabelWritable(dir string) bool {
	if err := setLowLabelPath(dir); err == nil {
		b.lowLabeled = append(b.lowLabeled, dir)
		return true
	} else if !isAccessDenied(err) {
		log.DebugSub(log.SubContainer, "restricted: low-label %s: %v", dir, err)
		return false
	}
	// ACCESS_DENIED — try the owner self-ACE path.
	if b.userSID == nil || !ownedBySID(dir, b.userSID) {
		log.DebugSub(log.SubContainer, "restricted: low-label %s denied and not owned by self; left Medium", dir)
		return false
	}
	if err := addSelfFullACE(dir, b.userSID); err != nil {
		log.DebugSub(log.SubContainer, "restricted: self-ACE on %s: %v", dir, err)
		return false
	}
	b.selfACEPaths = append(b.selfACEPaths, dir)
	if err := setLowLabelPath(dir); err != nil {
		log.DebugSub(log.SubContainer, "restricted: low-label %s after self-ACE: %v", dir, err)
		return false
	}
	b.lowLabeled = append(b.lowLabeled, dir)
	return true
}

// Cleanup terminates the process if still running, closes all handles,
// revokes per-session DACL DENY stamps, and removes the scratch dir.
//
// CRITICAL: the DENY revoke must run on every exit path. Without it,
// the user is locked out of their own credential paths until they
// manually undo the ACEs. revokeStampsParallel applies a 3 s wall-
// clock deadline so an unresponsive NTFS journal cannot stall dizgin's
// post-exit return.
func (b *box) Cleanup() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.started && !b.done && b.procH != 0 {
		_ = windows.TerminateProcess(b.procH, 1)
	}
	if b.threadH != 0 {
		_ = windows.CloseHandle(b.threadH)
		b.threadH = 0
	}
	if b.procH != 0 {
		_ = windows.CloseHandle(b.procH)
		b.procH = 0
	}
	if b.jobH != 0 {
		_ = windows.CloseHandle(b.jobH)
		b.jobH = 0
	}
	if b.stdio != nil {
		b.stdio.closeAll()
		b.stdio = nil
	}
	if b.conpty != nil {
		_ = b.conpty.Close()
		b.conpty = nil
	}

	// Revert Low-IL writable-set labels back to Medium. This must run
	// BEFORE revoking any self-ACE: removeLowLabelPath writes the mandatory
	// label, which needs the WRITE_OWNER that the self-ACE grants.
	for _, p := range b.lowLabeled {
		if err := removeLowLabelPath(p); err != nil {
			log.DebugSub(log.SubContainer, "restricted: revert low-label %s: %v", p, err)
		}
	}
	b.lowLabeled = nil

	// Revoke the temporary self-ACEs applyLowLabels added to make
	// otherwise-unrelabellable workdirs writable. Done after the label
	// revert above so the revert still had its WRITE_OWNER.
	for _, p := range b.selfACEPaths {
		if err := revokeSelfFullACE(p, b.userSID); err != nil {
			log.DebugSub(log.SubContainer, "restricted: revoke self-ACE %s: %v", p, err)
		}
	}
	b.selfACEPaths = nil

	if os.Getenv(brand.Env("TRACE_CLEANUP")) == "1" {
		fmt.Fprintln(os.Stderr, "TRACE cleanup: RevokeStamps loop")
	}
	// Revoke DENY ACEs on every successfully-stamped sensitive path.
	// 3 s wall-clock cap protects dizgin's exit latency.
	if len(b.deniedPaths) > 0 && b.userSID != nil {
		toRevoke := b.deniedPaths
		revokeStampsParallel(toRevoke, b.userSID)
		// Audit revoke after the parallel sweep so a post-mortem can
		// see exactly which paths got their DENY lifted. We log
		// regardless of per-path success — the parallel sweep is
		// best-effort with a 3 s deadline and the audit JSONL is the
		// only place this intent is recorded.
		for _, p := range toRevoke {
			audit.LogMountDecision(b.sessionID, audit.MountDecision{
				Category: "sensitive",
				Host:     p,
				Granted:  false,
				Reason:   "deny_revoked",
			})
		}
		b.deniedPaths = nil
	}
	if os.Getenv(brand.Env("TRACE_CLEANUP")) == "1" {
		fmt.Fprintln(os.Stderr, "TRACE cleanup: RevokeStamps done")
	}

	if b.scratchDir != "" {
		runWithDeadline("RemoveScratch", 2*time.Second, func() {
			if err := os.RemoveAll(b.scratchDir); err != nil {
				log.DebugSub(log.SubContainer, "restricted: RemoveAll(%s): %v",
					b.scratchDir, err)
			}
		})
		b.scratchDir = ""
	}
	return nil
}
