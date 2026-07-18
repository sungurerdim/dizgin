// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// kernel32.dll Job Object APIs.
//
// Job Objects scope the spawned process tree at the kernel level: they
// terminate every member when the parent dies (KILL_ON_JOB_CLOSE), cap
// memory, cap PID count, and freeze user-input handles. Combined with
// the restricted token (CreateRestrictedToken + Medium IL) and the
// per-child process mitigation policy bitfield they form the three
// kernel-enforced legs of the iter6 `restricted` backend.
//
// The OS schedules these limits independently of the token identity,
// so a per-session Job is created even when resource limits are zero —
// the UI restrictions alone are worth it.
var (
	modKernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procCreateJobObjectW         = modKernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = modKernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = modKernel32.NewProc("AssignProcessToJobObject")
)

// JobObjectInformationClass values from winnt.h. Only the classes we
// actually pass are listed; unused enumerants stay omitted to keep the
// surface minimal.
const (
	jobObjectBasicUIRestrictions      = 4
	jobObjectExtendedLimitInformation = 9
)

// JOBOBJECT_BASIC_LIMIT_INFORMATION mirrors the winnt.h struct of the
// same name. Padding is explicit so the layout matches the C ABI on
// both x86 and amd64.
type jobBasicLimitInformation struct {
	PerProcessUserTimeLimit uint64
	PerJobUserTimeLimit     uint64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type jobExtendedLimitInformation struct {
	BasicLimitInformation jobBasicLimitInformation
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

type jobBasicUIRestrictions struct {
	UIRestrictionsClass uint32
}

// JOB_OBJECT_LIMIT_* flag values. We use only the kill-on-close + the
// counted limits; the rest are documented for grep-ability when extending.
const (
	jobLimitKillOnJobClose = 0x00002000
	jobLimitActiveProcess  = 0x00000008
	jobLimitProcessMemory  = 0x00000100
)

// JOB_OBJECT_UILIMIT_* flag values. We always set the conservative full
// suite — the spawned tool has no business reading host clipboard,
// sending user input messages to other windows, or hooking foreign
// processes.
const (
	jobUILimitHandles         = 0x00000001
	jobUILimitReadClipboard   = 0x00000002
	jobUILimitWriteClipboard  = 0x00000004
	jobUILimitSystemParams    = 0x00000008
	jobUILimitDisplaySettings = 0x00000010
	jobUILimitGlobalAtoms     = 0x00000020
	jobUILimitDesktop         = 0x00000040
	jobUILimitExitWindows     = 0x00000080
)

// JobLimits captures the resource caps applied to the per-session
// Job Object. Zero fields mean "unlimited" — matching the
// sandbox.ResourceLimits convention so callers can pass values straight
// through without remapping.
type JobLimits struct {
	MemoryMB int
	MaxPIDs  int
}

// CreateJob creates a new unnamed Job Object, configures the kill-on-
// job-close + UI restriction + resource limits, and returns the handle.
// Caller is responsible for AssignProcessToJob and CloseHandle.
func CreateJob(limits JobLimits) (windows.Handle, error) {
	r1, _, e := procCreateJobObjectW.Call(0, 0)
	if r1 == 0 {
		return 0, fmt.Errorf("restricted: CreateJobObjectW: %w", e)
	}
	job := windows.Handle(r1)

	// Extended basic limit: kill on close + active process + memory.
	var ext jobExtendedLimitInformation
	ext.BasicLimitInformation.LimitFlags = jobLimitKillOnJobClose
	if limits.MaxPIDs > 0 {
		ext.BasicLimitInformation.LimitFlags |= jobLimitActiveProcess
		ext.BasicLimitInformation.ActiveProcessLimit = uint32(limits.MaxPIDs)
	}
	if limits.MemoryMB > 0 {
		ext.BasicLimitInformation.LimitFlags |= jobLimitProcessMemory
		ext.ProcessMemoryLimit = uintptr(limits.MemoryMB) << 20
	}
	if r2, _, e2 := procSetInformationJobObject.Call(
		uintptr(job),
		uintptr(jobObjectExtendedLimitInformation),
		uintptr(unsafe.Pointer(&ext)),
		unsafe.Sizeof(ext),
	); r2 == 0 {
		_ = windows.CloseHandle(job)
		return 0, fmt.Errorf("restricted: SetInformationJobObject(extended): %w", e2)
	}

	// UI restrictions — same conservative set Edge/Chrome stamp on their
	// renderers. Blocks USER handle inheritance, clipboard, system params,
	// global atoms, foreign desktop access and ExitWindows.
	ui := jobBasicUIRestrictions{
		UIRestrictionsClass: jobUILimitHandles |
			jobUILimitReadClipboard |
			jobUILimitWriteClipboard |
			jobUILimitSystemParams |
			jobUILimitDisplaySettings |
			jobUILimitGlobalAtoms |
			jobUILimitDesktop |
			jobUILimitExitWindows,
	}
	if r2, _, e2 := procSetInformationJobObject.Call(
		uintptr(job),
		uintptr(jobObjectBasicUIRestrictions),
		uintptr(unsafe.Pointer(&ui)),
		unsafe.Sizeof(ui),
	); r2 == 0 {
		_ = windows.CloseHandle(job)
		return 0, fmt.Errorf("restricted: SetInformationJobObject(ui): %w", e2)
	}
	return job, nil
}

// AssignProcessToJob attaches a process handle to a Job Object so the
// kernel applies all configured limits (and tears down the process tree
// when the Job handle is closed).
func AssignProcessToJob(job, proc windows.Handle) error {
	r1, _, e := procAssignProcessToJobObject.Call(uintptr(job), uintptr(proc))
	if r1 == 0 {
		return fmt.Errorf("restricted: AssignProcessToJobObject: %w", e)
	}
	return nil
}
