// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Process-spawn pipeline helpers extracted from box.Start (Phase 5
// behaviour-preserving refactor). Lifetime contract: every helper that
// allocates a buffer the kernel reads during CreateProcessAsUserW
// RETURNS it to Start, which keeps it in a local for the whole spawn.
// The single syscall + its runtime.KeepAlive guards live together in
// spawnProcess so the addressability window is auditable in one place.

// setupPTAL allocates + initialises the PROC_THREAD_ATTRIBUTE_LIST and
// applies the per-child mitigation policy. Returns the backing buffer
// (the caller MUST keep it alive until after the spawn), the list
// pointer (the caller installs the DeleteProcThreadAttributeList defer),
// and the mitigation flags pointer (kept alive until the spawn).
func (b *box) setupPTAL() (listBuf []byte, listPtr unsafe.Pointer, flagsPtr *uint64, err error) {
	ptalEntries := b.procThreadAttributeListEntriesCount()
	var listSize uintptr
	_, _, _ = procInitializeProcThreadAttributeList.Call(
		0,
		uintptr(ptalEntries),
		0,
		uintptr(unsafe.Pointer(&listSize)),
	)
	if listSize == 0 {
		return nil, nil, nil, fmt.Errorf("restricted: InitializeProcThreadAttributeList sized to 0")
	}
	listBuf = make([]byte, listSize)
	listPtr = unsafe.Pointer(&listBuf[0])

	if r, _, e := procInitializeProcThreadAttributeList.Call(
		uintptr(listPtr),
		uintptr(ptalEntries),
		0,
		uintptr(unsafe.Pointer(&listSize)),
	); r == 0 {
		return nil, nil, nil, fmt.Errorf("restricted: InitializeProcThreadAttributeList: %w", e)
	}

	// ACG (Dynamic Code PROHIBIT) is OFF by default — see
	// mitigation_windows.go for the CLAUDE-HANG-01 rationale.
	flagsPtr, err = applyChildMitigationPTAL(listPtr, b.policies)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("restricted: %w", err)
	}
	return listBuf, listPtr, flagsPtr, nil
}

// setupStdio prepares the child's standard handles + the STARTUPINFOEXW
// that references the PTAL.
//
// PTY mode: attaches the pseudoconsole (allocated in Start) via
// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE. The kernel wires the child's
// stdio to the ConDrv endpoints, so there are no inheritable stdio
// handles, no STARTF_USESTDHANDLES, and no handle-list allowlist. The
// returned *stdio is nil and the spawn runs with bInheritHandles=FALSE.
//
// Pipe mode: builds the owned stdio pipes (user-SID-granted), points
// STARTF_USESTDHANDLES at them, and adds the optional handle-list
// allowlist. On error the pipes are closed before returning.
// allowedHandles must be kept alive by the caller until after the spawn.
func (b *box) setupStdio(listPtr unsafe.Pointer) (*stdio, startupinfoExW, []windows.Handle, error) {
	si := startupinfoExW{}
	si.StartupInfo.Cb = uint32(unsafe.Sizeof(si))
	si.AttributeList = listPtr

	if b.usePTY {
		// STARTF_USESTDHANDLES with NULL std-handle fields is required:
		// it tells CreateProcess to take the child's stdio from the
		// pseudoconsole (supplied via the PSEUDOCONSOLE attribute) rather
		// than letting the child fall back to the parent's inherited
		// handles. Without the flag the child attaches to the
		// pseudoconsole for control but keeps inherited std handles, so
		// isatty stays false and the TTY is lost.
		si.StartupInfo.Flags = windows.STARTF_USESTDHANDLES
		if err := applyPseudoConsolePTAL(listPtr, b.conpty.hpc); err != nil {
			return nil, startupinfoExW{}, nil, fmt.Errorf("restricted: %w", err)
		}
		return nil, si, nil, nil
	}

	stdioPipes, err := newStdio(b.userSID)
	if err != nil {
		return nil, startupinfoExW{}, nil, fmt.Errorf("restricted: create stdio pipes: %w", err)
	}
	si.StartupInfo.Flags = windows.STARTF_USESTDHANDLES
	si.StartupInfo.StdInput = stdioPipes.stdinChild
	si.StartupInfo.StdOutput = stdioPipes.stdoutChild
	si.StartupInfo.StdErr = stdioPipes.stderrChild

	var allowedHandles []windows.Handle
	if b.handleListAllowlistEnabled() {
		allowedHandles, err = applyHandleListAllowlist(listPtr, []windows.Handle{
			stdioPipes.stdinChild,
			stdioPipes.stdoutChild,
			stdioPipes.stderrChild,
		})
		if err != nil {
			stdioPipes.closeAll()
			return nil, startupinfoExW{}, nil, fmt.Errorf("restricted: %w", err)
		}
	}
	return stdioPipes, si, allowedHandles, nil
}

// buildProcArgs marshals the command line, optional workdir, and env
// block into the UTF-16 forms CreateProcessAsUserW expects. All returned
// buffers must stay addressable through the spawn.
func buildProcArgs(workdir, cmd string, args, env []string) (pCmdLine, pWorkdir *uint16, envBlock []uint16, err error) {
	cmdLine, err := buildCommandLine(cmd, args)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("restricted: build command line: %w", err)
	}
	pCmdLine, err = windows.UTF16PtrFromString(cmdLine)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("restricted: command line UTF16: %w", err)
	}
	if workdir != "" {
		pWorkdir, err = windows.UTF16PtrFromString(workdir)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("restricted: workdir UTF16: %w", err)
		}
	}
	envBlock, err = utf16Env(env)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("restricted: env block: %w", err)
	}
	return pCmdLine, pWorkdir, envBlock, nil
}

// spawnProcess issues CreateProcessAsUserW and keeps every kernel-read
// buffer addressable across the call via runtime.KeepAlive. Co-locating
// the syscall with its KeepAlive guards is deliberate: the
// UpdateProcThreadAttribute calls only recorded pointers, and the kernel
// re-reads them at creation time, so the buffers must not be collected
// or moved until this returns.
func spawnProcess(
	token windows.Token,
	si *startupinfoExW,
	pCmdLine, pWorkdir *uint16,
	envBlock []uint16,
	allowedHandles []windows.Handle,
	flagsPtr *uint64,
	listBuf []byte,
	inheritHandles bool,
) (windows.ProcessInformation, error) {
	const creationFlags = createUnicodeEnvironment | extendedStartupinfoPresent
	// PTY mode passes inheritHandles=FALSE: the child reaches its
	// pseudoconsole through PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, not via
	// inherited handles, so no inheritable-handle set crosses the
	// boundary. Pipe mode passes TRUE and scopes inheritance with the
	// HANDLE_LIST allowlist.
	bInherit := uintptr(0)
	if inheritHandles {
		bInherit = 1
	}
	var pi windows.ProcessInformation
	r, _, e := procCreateProcessAsUserW.Call(
		uintptr(token),
		0, // lpApplicationName — let the OS resolve from cmdLine
		uintptr(unsafe.Pointer(pCmdLine)),
		0, // lpProcessAttributes
		0, // lpThreadAttributes
		bInherit,
		uintptr(creationFlags),
		uintptr(unsafe.Pointer(&envBlock[0])),
		uintptr(unsafe.Pointer(pWorkdir)),
		uintptr(unsafe.Pointer(si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	runtime.KeepAlive(allowedHandles)
	runtime.KeepAlive(flagsPtr)
	runtime.KeepAlive(listBuf)
	runtime.KeepAlive(si)
	runtime.KeepAlive(pCmdLine)
	runtime.KeepAlive(pWorkdir)
	runtime.KeepAlive(envBlock)
	if r == 0 {
		return windows.ProcessInformation{}, fmt.Errorf("restricted: CreateProcessAsUserW: %w", e)
	}
	return pi, nil
}

// attachJob creates the Job Object and assigns the spawned process so
// kill-on-close + UI restrictions + memory cap take effect. On failure
// it terminates the orphaned child and closes its handles (an
// unsupervised child violates the R1 fail-closed contract) before
// returning the error.
func (b *box) attachJob(pi windows.ProcessInformation) (windows.Handle, error) {
	job, err := CreateJob(b.jobLimits)
	if err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		_ = windows.CloseHandle(pi.Process)
		_ = windows.CloseHandle(pi.Thread)
		return 0, fmt.Errorf("restricted: create job: %w", err)
	}
	if err := AssignProcessToJob(job, pi.Process); err != nil {
		_ = windows.CloseHandle(job)
		_ = windows.TerminateProcess(pi.Process, 1)
		_ = windows.CloseHandle(pi.Process)
		_ = windows.CloseHandle(pi.Thread)
		return 0, fmt.Errorf("restricted: assign job: %w", err)
	}
	return job, nil
}
