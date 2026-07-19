// SPDX-License-Identifier: MIT

//go:build darwin

package monitor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func collect(opts CollectOpts) (Metrics, error) {
	var m Metrics

	// --- Basic level: ps for memory + CPU ---
	if err := collectPS(opts.PID, &m); err != nil {
		return m, fmt.Errorf("monitor: ps: %w", err)
	}

	if opts.Level == LevelBasic {
		return m, nil
	}

	// --- Detailed level ---
	// macOS doesn't expose per-process I/O counters without dtrace (root) or CGO.
	// Future option: use proc_pid_rusage() via CGO with rusage_info_v4 struct
	// (ri_diskio_bytesread / ri_diskio_byteswritten fields).
	// IOReadBytes and IOWriteBytes remain 0 on macOS for now.
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

// collectPS uses ps to read memory (RSS) and CPU for a process.
func collectPS(pid int, m *Metrics) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ps", "-o", "rss=,pcpu=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return err
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) >= 1 {
		if kb, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
			m.MemoryBytes = kb * 1024
		}
	}
	if len(fields) >= 2 {
		if cpu, err := strconv.ParseFloat(fields[1], 64); err == nil {
			m.CPUPercent = cpu
		}
	}
	m.PIDs = 1
	return nil
}

// collectProcessTree uses pgrep -P recursively to find child processes.
//
// treeDeadline bounds the entire BFS walk (not just each pgrep call) so a
// pathologically deep or wide process tree cannot make one collection pass
// exceed the monitor's polling interval.
func collectProcessTree(rootPID int, m *Metrics) {
	const treeDeadline = 5 * time.Second
	deadline := time.Now().Add(treeDeadline)

	visited := map[int]bool{rootPID: true}
	queue := []int{rootPID}
	var children []int

	for len(queue) > 0 && time.Now().Before(deadline) {
		pid := queue[0]
		queue = queue[1:]
		pgCtx, pgCancel := context.WithTimeout(context.Background(), 3*time.Second)
		out, err := exec.CommandContext(pgCtx, "pgrep", "-P", strconv.Itoa(pid)).Output()
		pgCancel()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			cpid, err := strconv.Atoi(strings.TrimSpace(line))
			if err != nil || visited[cpid] {
				continue
			}
			visited[cpid] = true
			children = append(children, cpid)
			queue = append(queue, cpid)
		}
	}

	m.ChildPIDs = children
	m.PIDs = len(children) + 1

	// Thread count via ps.
	psCtx, psCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer psCancel()
	out, err := exec.CommandContext(psCtx, "ps", "-M", "-p", strconv.Itoa(rootPID)).Output()
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) > 1 {
			m.ThreadCount = len(lines) - 1 // subtract header
		}
	}
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
