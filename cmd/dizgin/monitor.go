// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/config"
	"github.com/sungurerdim/dizgin/internal/daemon"
	"github.com/sungurerdim/dizgin/internal/monitor"
	"github.com/sungurerdim/dizgin/internal/platform"
	"github.com/sungurerdim/dizgin/internal/sandbox"
)

// defaultMonitorInterval is the fallback interval for resource metric collection
// when no interval is specified in config.
const defaultMonitorInterval = 10 * time.Second

// registerWithDaemon connects to the daemon, registers this session,
// and wires suspend/resume/kill command handling.
func registerWithDaemon(toolBin, wd, backendName string, box sandbox.Box) *daemon.Client {
	daemonClient := daemon.NewClient(
		fmt.Sprintf("%d", os.Getpid()),
		toolBin,
		wd,
		backendName,
		os.Getpid(),
	)

	boxPid := box.Pid()
	daemonClient.SetCommandHandler(func(action daemon.CommandAction) {
		switch action {
		case daemon.ActionSuspend:
			platform.SuspendProcess(boxPid) //nolint:errcheck
		case daemon.ActionResume:
			platform.ResumeProcess(boxPid) //nolint:errcheck
		case daemon.ActionKill:
			box.Signal(os.Interrupt) //nolint:errcheck
		}
	})
	daemonClient.Start()
	return daemonClient
}

// parseMonitorLevel converts a config string to a monitor.Level constant.
func parseMonitorLevel(s string) monitor.Level {
	switch s {
	case "detailed":
		return monitor.LevelDetailed
	case "full":
		return monitor.LevelFull
	default:
		return monitor.LevelBasic
	}
}

// resolveMonitorInterval returns d if positive, else the fallback default.
// Config-file syntax errors are caught at Load() time (viper's duration
// decode hook); this only guards the zero-value/unset case.
func resolveMonitorInterval(d time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return defaultMonitorInterval
}

// boxJobHandle returns the OS-level job/cgroup handle for resource queries.
// Uses a type assertion against a narrow interface so monitor.go stays free
// of platform-specific imports — only the Windows restricted box implements
// JobHandle(); on other platforms 0 is returned and monitor.Collect no-ops.
func boxJobHandle(b sandbox.Box) uintptr {
	type jobHandleBox interface{ JobHandle() uintptr }
	if jb, ok := b.(jobHandleBox); ok {
		return jb.JobHandle()
	}
	return 0
}

// newMetricsReporter returns a closure that collects resource metrics from the
// sandbox and sends them to the daemon. The closure captures its own error
// state so the first collection error is logged once without requiring the
// caller to manage a pointer-to-bool.
func newMetricsReporter(box sandbox.Box, client *daemon.Client, level monitor.Level, startTime time.Time) func() {
	errLogged := false
	return func() {
		m, err := monitor.Collect(monitor.CollectOpts{
			PID:       box.Pid(),
			JobHandle: boxJobHandle(box),
			TempDir:   boxTempDir(box),
			Level:     level,
			StartTime: startTime,
		})
		if err != nil && !errLogged {
			fmt.Fprintf(os.Stderr, brand.Name+": monitor: %v\n", err)
			errLogged = true
		}
		client.HeartbeatWithMetrics(
			string(daemon.StatusRunning), "",
			m.MemoryBytes, m.CPUPercent, m.PIDs,
			m.IOReadBytes, m.IOWriteBytes, m.DiskUsageBytes,
			int64(m.Uptime.Seconds()),
			m.ThreadCount, m.HandleCount, m.ChildPIDs,
		)
	}
}

// startMonitor launches a background goroutine that periodically collects resource
// metrics from the sandboxed process and sends them via daemon heartbeats.
// Returns a stop function that halts the goroutine.
func startMonitor(cfg *config.Config, box sandbox.Box, client *daemon.Client) func() {
	level := parseMonitorLevel(cfg.Monitor.Level)
	interval := resolveMonitorInterval(cfg.Monitor.Interval)
	stopCh := make(chan struct{})
	startTime := time.Now()
	report := newMetricsReporter(box, client, level, startTime)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				report()
			}
		}
	}()

	return func() {
		select {
		case <-stopCh:
		default:
			close(stopCh)
		}
	}
}
