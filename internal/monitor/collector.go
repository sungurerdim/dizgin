// SPDX-License-Identifier: MIT

// Package monitor provides resource metrics collection for sandboxed sessions.
// It queries OS-level process and job-object data to report memory, CPU, I/O,
// and process-tree information without interfering with sandbox operation.
package monitor

import "time"

// Level controls the depth of metrics collection.
type Level string

const (
	// LevelBasic collects memory, CPU, and PID count.
	LevelBasic Level = "basic"
	// LevelDetailed adds I/O bytes, disk usage, and uptime.
	LevelDetailed Level = "detailed"
	// LevelFull adds thread count, handle count, and child process tree.
	LevelFull Level = "full"
)

// Metrics holds a point-in-time resource snapshot of a sandboxed session.
// Fields beyond the requested Level are left at their zero value.
type Metrics struct {
	ChildPIDs      []int
	MemoryBytes    uint64
	CPUPercent     float64
	PIDs           int
	IOReadBytes    uint64
	IOWriteBytes   uint64
	DiskUsageBytes uint64
	Uptime         time.Duration
	ThreadCount    int
	HandleCount    int
}

// CollectOpts carries the parameters needed by Collect.
type CollectOpts struct {
	StartTime time.Time
	TempDir   string
	Level     Level
	PID       int
	JobHandle uintptr
}

// Collect gathers resource metrics for the sandboxed process tree.
// The implementation is platform-specific; see collector_windows.go,
// collector_unix.go, and collector_darwin.go.
func Collect(opts CollectOpts) (Metrics, error) {
	return collect(opts)
}
