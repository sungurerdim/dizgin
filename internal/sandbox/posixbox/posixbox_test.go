// SPDX-License-Identifier: MIT

//go:build darwin || linux

package posixbox

import (
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/sungurerdim/dizgin/internal/platform"
)

// TestMain intercepts two special re-execs of this same test binary and
// turns them into controllable child processes instead of running the test
// suite again — the standard os/exec testing idiom for getting real child
// processes without depending on any external binary (sleep, cat, ...)
// being present on the host.
//
//   - POSIXBOX_TEST_SIGTERM_MARKER=<path>: writes <path>.ready as soon as
//     its SIGTERM handler is installed, blocks until SIGTERM arrives, then
//     writes <path> and exits. Used as the "grandchild" in
//     TestStartWithPTY_SignalReachesEntireProcessGroup — checked first so
//     it works whether or not POSIXBOX_TEST_HELPER is also set (the
//     grandchild inherits the parent helper's env wholesale).
//   - POSIXBOX_TEST_HELPER=1: blocks on stdin, exits 0 when it's closed.
//     If POSIXBOX_TEST_SPAWN_GRANDCHILD=<path> is also set, it first
//     spawns its own child (re-exec, POSIXBOX_TEST_SIGTERM_MARKER=<path>)
//     in the same process group before blocking — this is the "middle"
//     process StartWithPTY starts directly.
func TestMain(m *testing.M) {
	if marker := os.Getenv("POSIXBOX_TEST_SIGTERM_MARKER"); marker != "" {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM)
		_ = os.WriteFile(marker+".ready", []byte("ready"), 0o600)
		<-sigCh
		_ = os.WriteFile(marker, []byte("signaled"), 0o600)
		os.Exit(0)
	}
	if os.Getenv("POSIXBOX_TEST_HELPER") == "1" {
		if marker := os.Getenv("POSIXBOX_TEST_SPAWN_GRANDCHILD"); marker != "" {
			gc := exec.Command(os.Args[0]) //nolint:gosec // same re-exec idiom as helperCommand
			gc.Env = append(os.Environ(), "POSIXBOX_TEST_SIGTERM_MARKER="+marker)
			_ = gc.Start()
		}
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func helperCommand(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0]) //nolint:gosec // G204 false positive: standard os/exec test idiom, re-execs this same test binary, not user input
	cmd.Env = append(os.Environ(), "POSIXBOX_TEST_HELPER=1")
	return cmd
}

func TestLifecycle_ZeroValue_NoOpBeforeStart(t *testing.T) {
	var l Lifecycle
	if pid := l.Pid(); pid != 0 {
		t.Errorf("Pid() before start = %d, want 0", pid)
	}
	if err := l.Signal(os.Interrupt); err != nil {
		t.Errorf("Signal() before start: got %v, want nil (no-op)", err)
	}
	if rwc := l.PTY(); rwc != nil {
		t.Errorf("PTY() with no session = %v, want nil", rwc)
	}
}

func TestLifecycle_PidAndSignal_RealProcess(t *testing.T) {
	cmd := helperCommand(t)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	l := &Lifecycle{Cmd: cmd}

	if pid := l.Pid(); pid <= 0 {
		t.Errorf("Pid() = %d, want > 0 for a running process", pid)
	}

	// Signal(0) is a portable "is it alive" probe: no actual signal is
	// delivered, but the kernel still validates the target exists.
	if err := l.Signal(syscall.Signal(0)); err != nil {
		t.Errorf("Signal(0) probe on live process: %v", err)
	}

	stdin.Close() //nolint:errcheck // closing stdin is how the helper knows to exit

	code, err := l.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !l.Done {
		t.Error("Done should be true after Wait returns")
	}

	// Signaling an already-reaped process is expected to surface an error
	// from the runtime (os.ErrProcessDone) — callers in this codebase
	// intentionally discard it (best-effort signal delivery), but the
	// Lifecycle method itself must propagate it rather than swallow it.
	if err := l.Signal(os.Interrupt); err == nil {
		t.Error("Signal() after process exit: want an error, got nil")
	}
}

// TestStartWithPTY_SignalReachesEntireProcessGroup pins the fix for a real
// bug: Lifecycle.Signal used to call cmd.Process.Signal, which only ever
// reaches the direct child — a subprocess the sandboxed tool spawns (an
// MCP server, git, node) kept running as an orphan after dizgin forwarded
// SIGTERM/SIGINT, unlike a native shell's job control, where a signal to
// the foreground process group reaches every process in it. Since
// StartWithPTY always sets Setsid, the child is its own process-group
// leader (pgid == pid); Signal() must target -pid, not pid, whenever a PTY
// session is active.
func TestStartWithPTY_SignalReachesEntireProcessGroup(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "grandchild-signaled")
	ready := marker + ".ready"

	cmd := helperCommand(t)
	cmd.Env = append(cmd.Env, "POSIXBOX_TEST_SPAWN_GRANDCHILD="+marker)

	sess, err := StartWithPTY(cmd)
	if err != nil {
		t.Fatalf("StartWithPTY: %v", err)
	}
	defer sess.Close()
	l := &Lifecycle{Cmd: cmd, Session: sess}

	// Wait for the grandchild to confirm its SIGTERM handler is installed
	// before signaling — proves the handler was live, not a race won by
	// sheer luck.
	waitForFile(t, ready, 2*time.Second)

	if err := l.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("Signal: %v", err)
	}

	// The test never held a direct reference to the grandchild's pid —
	// only Lifecycle, which only knows the middle process, does. The
	// marker file appearing proves Signal() reached the grandchild too,
	// i.e. the whole process group, not just the direct child.
	waitForFile(t, marker, 2*time.Second)

	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}

// waitForFile polls for path to exist, failing the test if it doesn't
// appear within timeout.
func waitForFile(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}

func TestStartWithPTY_AllocatesReadWriteCloser(t *testing.T) {
	cmd := helperCommand(t)
	sess, err := StartWithPTY(cmd)
	if err != nil {
		t.Fatalf("StartWithPTY: %v", err)
	}
	defer sess.Close()

	if rwc := sess.RWC(); rwc == nil {
		t.Fatal("RWC() returned nil")
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	_ = cmd.Wait()
}

// TestStartWithPTY_InnerPTYIsRawBeforeChildRuns pins the fix for a real
// bug: pty.Start(cmd) alone leaves the slave in the kernel's default
// cooked mode (ICANON+ECHO on) until the child's own runtime flips it,
// which is a race the child can lose — e.g. a TUI's startup work delaying
// its raw-mode call, or a terminal capability query/response dizgin
// relays arriving during that window. Cooked mode then echoes bytes
// written into the pty straight back out (visible as garbled on-screen
// text) and line-buffers input until a newline (swallowing single
// keypresses like a bare "1"/"2" at a y/n prompt). StartWithPTY must set
// raw mode itself, synchronously, before cmd.Start() — this test asserts
// that invariant holds the instant StartWithPTY returns, with no window
// at all where the child could observe cooked mode.
func TestStartWithPTY_InnerPTYIsRawBeforeChildRuns(t *testing.T) {
	cmd := helperCommand(t)
	sess, err := StartWithPTY(cmd)
	if err != nil {
		t.Fatalf("StartWithPTY: %v", err)
	}
	defer sess.Close()
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	raw, err := platform.IsRaw(sess.ptmx)
	if err != nil {
		t.Fatalf("IsRaw: %v", err)
	}
	if !raw {
		t.Error("inner PTY is not in raw mode immediately after StartWithPTY returns — ICANON/ECHO should already be off, not left for the sandboxed tool's own runtime to disable")
	}
}

func TestLifecycle_PTY_ReturnsSessionRWC(t *testing.T) {
	cmd := helperCommand(t)
	sess, err := StartWithPTY(cmd)
	if err != nil {
		t.Fatalf("StartWithPTY: %v", err)
	}
	defer sess.Close()

	l := &Lifecycle{Cmd: cmd, Session: sess}
	if l.PTY() == nil {
		t.Error("Lifecycle.PTY() should return the session's RWC")
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	_ = cmd.Wait()
}

func TestLifecycle_Wait_NonZeroExit(t *testing.T) {
	// A helper invocation that is NOT given the env var falls through to
	// TestMain's m.Run() branch, which runs this package's test suite and
	// exits with go test's own status — not useful here. Instead, exploit
	// the helper's actual behavior: closing stdin makes it exit 0. To get
	// a non-zero exit deterministically without a second binary, signal
	// the helper to death and assert Wait() surfaces that as a non-nil
	// error path (the *exec.ExitError branch is exercised by the zero-exit
	// case above; the "err != ExitError" branch needs a kill).
	cmd := helperCommand(t)
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	l := &Lifecycle{Cmd: cmd}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("Kill: %v", err)
	}

	code, err := l.Wait()
	// A killed process reports as an *exec.ExitError (non-zero/signaled
	// code), which Wait() still classifies as "err == nil" from Wait()'s
	// perspective (code, nil) since exec.ExitError is handled internally.
	if err != nil {
		t.Fatalf("Wait after Kill: %v", err)
	}
	if code == 0 {
		t.Error("exit code after Kill: want non-zero, got 0")
	}
	if !l.Done {
		t.Error("Done should be true after Wait returns, even on a killed process")
	}
}
