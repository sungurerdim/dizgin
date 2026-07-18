// SPDX-License-Identifier: MIT

//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/daemon"
)

// ensureDaemonRunning checks if the dizgind daemon is reachable.
// If not, spawns "dizgind start" in the background and waits for it to
// become available. dizgind handles its own UAC elevation.
//
// Graceful degradation:
//   - DIZGIN_NO_DAEMON_AUTOSTART=1 skips the autostart entirely. dizgin still
//     attempts to talk to the daemon later — the difference is that we
//     do not block here trying to bring it up. Test harnesses set this
//     so suite startup is not held hostage by a missing daemon.
//   - When dizgind is on PATH but does not respond, we cap the wait at
//     15 s. iter6 removed the cold-start path that used to take 5 min
//     while `dizgind setup` stamped volume roots; the restricted token
//     preserves SeChangeNotify so NTFS traversal works without that
//     setup.
func ensureDaemonRunning() {
	if os.Getenv(brand.Env("NO_DAEMON_AUTOSTART")) == "1" {
		return
	}
	if daemon.IsDaemonRunning() {
		return
	}

	daemonPath := findDaemonBinary()
	if daemonPath == "" {
		fmt.Fprintln(os.Stderr, brand.Name+": dizgind not found — install it or add to PATH")
		fmt.Fprintln(os.Stderr, brand.Name+": degraded without dizgind: suspend/resume, `dizgind status` reporting, and WFP network-allowlist enforcement are unavailable.")
		fmt.Fprintln(os.Stderr, brand.Name+": the sandbox itself (R1 filesystem DENY, restricted token, Job Object) still works fully.")
		return
	}

	fmt.Fprintln(os.Stderr, brand.Name+": starting dizgind daemon...")

	cmd := exec.Command(daemonPath, "start")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, brand.Name+": failed to start dizgind: %v\n", err)
		return
	}

	// Wait for daemon to become available. 15 s cap matches the warm-
	// start ceiling — `dizgind start` itself raises UAC for the elevated
	// daemon and the prompt acceptance latency dominates the wait.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		if daemon.IsDaemonRunning() {
			return
		}
	}
	fmt.Fprintln(os.Stderr, brand.Name+": dizgind daemon did not start in time — continuing without it")
	fmt.Fprintln(os.Stderr, brand.Name+": degraded: suspend/resume, status reporting, and WFP network-allowlist enforcement unavailable. Run `dizgin doctor` to diagnose. The sandbox itself still works.")
}

// findDaemonBinary locates the dizgind binary.
func findDaemonBinary() string {
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		for _, name := range []string{brand.DaemonName + ".exe", brand.DaemonName} {
			p := filepath.Join(exeDir, name)
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	if p, err := exec.LookPath(brand.DaemonName); err == nil {
		return p
	}
	return ""
}
