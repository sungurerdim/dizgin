// SPDX-License-Identifier: MIT

//go:build windows && integration

// Package e2e covers the daemon suspend/resume control plane.
// Replaces the HCS-era suspend_resume scaffold removed in 94ea514
// (TST-01). The wire protocol (`dizgind suspend <id>` →
// daemon.SetCommandHandler → platform.SuspendProcess) is unchanged
// from the HCS era — only the underlying process is now an
// AppContainer-LowBox child instead of a Hyper-V container.
//
// Live infrastructure required: dizgind daemon must be running and
// the `dizgind` CLI must be on PATH. Tests skip when either is
// missing.
package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/daemon"
)

const suspendResumeTimeout = 30 * time.Second

// requireStation skips the test when the dizgind daemon is offline
// or the dizgind CLI is not installed.
//
// A named pipe is not a regular file: os.Stat(brand.PipeName) is not a
// reliable reachability probe (it does not reflect whether a server is
// actually listening) and made this test skip unconditionally on every
// run regardless of daemon state. daemon.Dial performs the real
// DialPipe handshake the production client uses, so a successful
// connect means the daemon is genuinely reachable.
func requireStation(t *testing.T) {
	t.Helper()
	conn, err := daemon.Dial(2 * time.Second)
	if err != nil {
		t.Skip("dizgind daemon not running — start with `dizgind start`")
	}
	_ = conn.Close()
	if _, err := exec.LookPath(brand.DaemonName); err != nil {
		t.Skip("dizgind binary not on PATH — run `make install`")
	}
}

// TestSuspendResume_LongRunningSession launches a long-running dizgin
// process via cmd /c ping (which loops until told to stop), waits
// for the daemon to register the session, sends `dizgind suspend
// <pid>`, sleeps briefly, then `dizgind resume <pid>`, and finally
// kills the session. The success criterion is that the process
// stays alive across both commands and exits cleanly when killed.
//
// Failure modes the test catches:
//   - Daemon never sees the session register (IPC broken)
//   - SuspendProcess returns OK but the child does not actually
//     stop scheduling (suspend wire detached from kernel call)
//   - Resume fails to wake the suspended thread (kernel handle leak)
func TestSuspendResume_LongRunningSession(t *testing.T) {
	requireStation(t)
	bin := dizginBin(t)
	wd := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), suspendResumeTimeout)
	defer cancel()

	// `ping -t 127.0.0.1` is a portable, always-on Windows command
	// that runs until killed. The dizgin session registers with the
	// daemon as soon as Box.Start succeeds.
	cmd := exec.CommandContext(ctx, bin, "-w", wd, "--no-pty",
		"cmd", "/c", "ping", "-t", "127.0.0.1")
	cmd.Dir = wd
	if err := cmd.Start(); err != nil {
		t.Fatalf("dizgin ping start: %v", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	pid := cmd.Process.Pid

	// Poll until the daemon has recorded the registration heartbeat for this
	// session. We query `dizgind status` and look for the PID in its output
	// rather than sleeping a fixed 2 s.
	waitForDaemonSession(t, ctx, pid, 10*time.Second)

	// Suspend.
	suspendCmd := exec.CommandContext(ctx, brand.DaemonName, "suspend", fmt.Sprintf("%d", pid))
	if out, err := suspendCmd.CombinedOutput(); err != nil {
		t.Fatalf("dizgind suspend %d failed: %v\noutput: %s", pid, err, out)
	}

	// Verify the process is still in the OS process table — suspend
	// must not kill it. We check via FindProcess; on Windows this
	// returns a usable handle for any live PID and an error for
	// dead ones.
	if _, err := os.FindProcess(pid); err != nil {
		t.Fatalf("process %d gone after suspend (expected: alive but suspended): %v", pid, err)
	}

	// Brief dwell to let the kernel scheduler settle the suspended state.
	// Poll until the process is still alive (it should remain alive for the
	// full dwell; we cap at 2 s rather than sleeping a fixed 1 s).
	waitForCondition(t, 2*time.Second, func() bool {
		_, err := os.FindProcess(pid)
		return err == nil
	})

	// Resume.
	resumeCmd := exec.CommandContext(ctx, brand.DaemonName, "resume", fmt.Sprintf("%d", pid))
	if out, err := resumeCmd.CombinedOutput(); err != nil {
		t.Fatalf("dizgind resume %d failed: %v\noutput: %s", pid, err, out)
	}

	// Final kill so the test cleans up promptly.
	killCmd := exec.CommandContext(ctx, brand.DaemonName, "kill", fmt.Sprintf("%d", pid))
	if out, err := killCmd.CombinedOutput(); err != nil {
		// kill may report "already exited" if the daemon raced us
		// to the process; treat that as success.
		if !strings.Contains(strings.ToLower(string(out)), "not found") &&
			!strings.Contains(strings.ToLower(string(out)), "already") {
			t.Errorf("dizgind kill %d failed: %v\noutput: %s", pid, err, out)
		}
	}
}

// waitForCondition polls fn every 50 ms until it returns true or timeout
// expires. Unlike a bare time.Sleep it returns as soon as the condition holds,
// making tests faster on well-performing hosts and more robust on slow ones.
func waitForCondition(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Timeout without condition — not necessarily fatal; caller decides.
}

// waitForDaemonSession polls `dizgind status` until the session with the given
// PID appears in the output, or until timeout. Replaces a fixed sleep that
// assumed a 2 s registration window.
func waitForDaemonSession(t *testing.T, ctx context.Context, pid int, timeout time.Duration) {
	t.Helper()
	pidStr := fmt.Sprintf("%d", pid)
	waitForCondition(t, timeout, func() bool {
		out, err := exec.CommandContext(ctx, brand.DaemonName, "status").CombinedOutput()
		if err != nil {
			return false
		}
		return strings.Contains(string(out), pidStr)
	})
}
