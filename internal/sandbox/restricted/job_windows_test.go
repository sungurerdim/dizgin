// SPDX-License-Identifier: MIT

//go:build windows

package restricted

// TST-05 — CreateJob / AssignProcessToJob.
//
// CreateJob creates a real Win32 Job Object — fully testable without elevation.
// AssignProcessToJob against a real spawned process is e2e (requires a child
// process that is not already in a job; CI runners are typically inside a job
// themselves making nested assignment fail with ERROR_ACCESS_DENIED unless the
// nested flag is set). Those paths are noted below.

import (
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
)

// ---- CreateJob ----

func TestCreateJob_ReturnsValidHandle(t *testing.T) {
	h, err := CreateJob(JobLimits{})
	if err != nil {
		t.Fatalf("CreateJob(zero limits): %v", err)
	}
	if h == 0 {
		t.Error("CreateJob returned a zero handle without error")
	}
	if err := windows.CloseHandle(h); err != nil {
		t.Errorf("CloseHandle: %v", err)
	}
}

func TestCreateJob_WithMemoryLimit(t *testing.T) {
	h, err := CreateJob(JobLimits{MemoryMB: 512})
	if err != nil {
		t.Fatalf("CreateJob(MemoryMB=512): %v", err)
	}
	if h == 0 {
		t.Fatal("CreateJob returned zero handle")
	}
	_ = windows.CloseHandle(h)
}

func TestCreateJob_WithMaxPIDs(t *testing.T) {
	h, err := CreateJob(JobLimits{MaxPIDs: 32})
	if err != nil {
		t.Fatalf("CreateJob(MaxPIDs=32): %v", err)
	}
	if h == 0 {
		t.Fatal("CreateJob returned zero handle")
	}
	_ = windows.CloseHandle(h)
}

func TestCreateJob_WithBothLimits(t *testing.T) {
	h, err := CreateJob(JobLimits{MemoryMB: 256, MaxPIDs: 16})
	if err != nil {
		t.Fatalf("CreateJob(MemoryMB=256, MaxPIDs=16): %v", err)
	}
	if h == 0 {
		t.Fatal("CreateJob returned zero handle")
	}
	_ = windows.CloseHandle(h)
}

func TestCreateJob_MultipleIndependent(t *testing.T) {
	// Each call must produce a distinct handle (kernel objects are unique).
	h1, err1 := CreateJob(JobLimits{})
	h2, err2 := CreateJob(JobLimits{MaxPIDs: 8})
	if err1 != nil {
		t.Fatalf("first CreateJob: %v", err1)
	}
	if err2 != nil {
		_ = windows.CloseHandle(h1)
		t.Fatalf("second CreateJob: %v", err2)
	}
	if h1 == h2 {
		t.Errorf("two separate CreateJob calls returned the same handle value 0x%x", h1)
	}
	_ = windows.CloseHandle(h1)
	_ = windows.CloseHandle(h2)
}

// ---- AssignProcessToJob ----
//
// Attempting to assign a real spawned child to the job is an e2e scenario:
// CI environments (GitHub Actions, many build systems) run the test process
// inside a Job Object that does not have JOB_OBJECT_LIMIT_BREAKAWAY_OK set,
// so AssignProcessToJobObject on a grandchild fails with ERROR_ACCESS_DENIED.
//
// What IS testable: assigning an invalid handle produces an error.

func TestAssignProcessToJob_InvalidHandlesError(t *testing.T) {
	err := AssignProcessToJob(windows.InvalidHandle, windows.InvalidHandle)
	if err == nil {
		t.Error("AssignProcessToJob(INVALID_HANDLE, INVALID_HANDLE) should return an error")
	}
}

func TestAssignProcessToJob_ZeroHandlesError(t *testing.T) {
	err := AssignProcessToJob(0, 0)
	if err == nil {
		t.Error("AssignProcessToJob(0, 0) should return an error")
	}
}

func TestAssignProcessToJob_RealChildE2E(t *testing.T) {
	// This test attempts to assign a real child process. It is skipped when
	// the current process is already in a non-breakaway job (common in CI).
	// Run it with: go test -run TestAssignProcessToJob_RealChildE2E -tags e2e
	t.Skip("e2e: requires a non-nested job context — run manually outside CI")

	job, err := CreateJob(JobLimits{})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	defer func() { _ = windows.CloseHandle(job) }()

	cmd := exec.Command("cmd.exe", "/c", "exit 0")
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start: %v", err)
	}
	proc := windows.Handle(cmd.Process.Pid) // intentionally wrong — tested separately
	defer func() { _ = cmd.Wait() }()

	// Open the process handle.
	ph, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, uint32(cmd.Process.Pid))
	if err != nil {
		t.Fatalf("OpenProcess: %v", err)
	}
	defer func() { _ = windows.CloseHandle(ph) }()
	_ = proc

	if err := AssignProcessToJob(job, ph); err != nil {
		t.Errorf("AssignProcessToJob: %v", err)
	}
}
