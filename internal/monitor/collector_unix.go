// SPDX-License-Identifier: MIT

//go:build linux

package monitor

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// clockTicksPerSec is the Linux USER_HZ constant (default on all standard kernels).
const clockTicksPerSec = 100

type cpuSample struct {
	ticks uint64
	wall  time.Time
}

var (
	cpuPrevMu sync.Mutex
	cpuPrev   = make(map[int]cpuSample)
)

func collect(opts CollectOpts) (Metrics, error) {
	var m Metrics

	// --- Basic level: /proc/<pid>/status for memory + /proc/<pid>/stat for CPU ---
	if err := collectProcStatus(opts.PID, &m); err != nil {
		return m, fmt.Errorf("monitor: proc status: %w", err)
	}
	collectProcStat(opts.PID, &m)
	m.PIDs = 1 + countChildren(opts.PID)

	if opts.Level == LevelBasic {
		return m, nil
	}

	// --- Detailed level ---
	collectProcIO(opts.PID, &m)
	if opts.TempDir != "" {
		m.DiskUsageBytes = dirSize(opts.TempDir)
	}
	if !opts.StartTime.IsZero() {
		m.Uptime = time.Since(opts.StartTime)
	}

	if opts.Level == LevelDetailed {
		return m, nil
	}

	// --- Full level ---
	collectProcessTree(opts.PID, &m)

	return m, nil
}

// collectProcStatus reads /proc/<pid>/status for VmRSS.
func collectProcStatus(pid int, m *Metrics) error {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if kb, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					m.MemoryBytes = kb * 1024
				}
			}
		}
		if strings.HasPrefix(line, "Threads:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if n, err := strconv.Atoi(fields[1]); err == nil {
					m.ThreadCount = n
				}
			}
		}
	}
	return nil
}

// collectProcStat reads /proc/<pid>/stat for CPU time.
func collectProcStat(pid int, m *Metrics) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return
	}
	// Fields after last ')': state, ppid, ... utime(14), stime(15), ...
	idx := strings.LastIndex(string(data), ")")
	if idx < 0 {
		return
	}
	fields := strings.Fields(string(data)[idx+2:])
	if len(fields) < 13 {
		return
	}
	utime, _ := strconv.ParseUint(fields[11], 10, 64)
	stime, _ := strconv.ParseUint(fields[12], 10, 64)
	totalTicks := utime + stime

	// Delta-based CPU percentage: compare current ticks with previous sample.
	now := time.Now()
	cpuPrevMu.Lock()
	prev, hasPrev := cpuPrev[pid]
	cpuPrev[pid] = cpuSample{ticks: totalTicks, wall: now}
	cpuPrevMu.Unlock()

	if hasPrev {
		wallDelta := now.Sub(prev.wall).Seconds()
		if wallDelta > 0 {
			tickDelta := float64(totalTicks-prev.ticks) / clockTicksPerSec
			m.CPUPercent = (tickDelta / wallDelta) * 100
		}
	}
}

// collectProcIO reads /proc/<pid>/io for I/O counters.
func collectProcIO(pid int, m *Metrics) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/io", pid))
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "read_bytes:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				m.IOReadBytes, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		}
		if strings.HasPrefix(line, "write_bytes:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				m.IOWriteBytes, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		}
	}
}

// countChildren counts direct child processes of pid.
func countChildren(pid int) int {
	children, _ := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if len(children) > 0 {
		return len(children) - 1 // subtract the main thread
	}
	return 0
}

// collectProcessTree walks /proc to find all descendants.
func collectProcessTree(rootPID int, m *Metrics) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}

	type proc struct {
		pid, ppid int
		threads   int
	}
	var procs []proc
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			continue
		}
		idx := strings.LastIndex(string(data), ")")
		if idx < 0 {
			continue
		}
		fields := strings.Fields(string(data)[idx+2:])
		if len(fields) < 18 {
			continue
		}
		ppid, _ := strconv.Atoi(fields[1])
		threads, _ := strconv.Atoi(fields[17])
		procs = append(procs, proc{pid: pid, ppid: ppid, threads: threads})
	}

	// BFS from rootPID.
	inTree := map[int]bool{rootPID: true}
	changed := true
	for changed {
		changed = false
		for _, p := range procs {
			if !inTree[p.pid] && inTree[p.ppid] {
				inTree[p.pid] = true
				changed = true
			}
		}
	}

	var children []int
	var totalThreads int
	for _, p := range procs {
		if inTree[p.pid] {
			if p.pid != rootPID {
				children = append(children, p.pid)
			}
			totalThreads += p.threads
		}
	}
	m.ChildPIDs = children
	m.ThreadCount = totalThreads
	m.PIDs = len(children) + 1
}

// dirSize walks a directory tree and sums file sizes.
func dirSize(path string) uint64 {
	var total uint64
	filepath.WalkDir(path, func(_ string, d os.DirEntry, err error) error { //nolint:errcheck
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err == nil {
			total += uint64(info.Size())
		}
		return nil
	})
	return total
}
