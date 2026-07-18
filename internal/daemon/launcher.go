// SPDX-License-Identifier: MIT

package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/log"
)

// Launcher manages spawning new dizgin sessions from the daemon.
type Launcher struct {
	// DizginBin is the path to the dizgin binary. Auto-detected if empty.
	DizginBin string
}

// NewLauncher creates a Launcher, auto-detecting the dizgin binary path.
func NewLauncher() *Launcher {
	bin := findDizginBinary()
	return &Launcher{DizginBin: bin}
}

// LaunchSession starts a new sandboxed session by spawning a dizgin process.
// Returns the PID of the spawned process.
func (l *Launcher) LaunchSession(tool, workdir string, args []string) (int, error) {
	if l.DizginBin == "" {
		return 0, fmt.Errorf("launcher: dizgin binary not found in PATH")
	}
	if tool == "" {
		return 0, fmt.Errorf("launcher: tool name required")
	}

	// Build command: dizgin [-w workdir] tool [args...]
	cmdArgs := []string{}
	if workdir != "" {
		cmdArgs = append(cmdArgs, "-w", workdir)
	}
	cmdArgs = append(cmdArgs, tool)
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.Command(l.DizginBin, cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if workdir != "" {
		cmd.Dir = workdir
	}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("launcher: start %s: %w", tool, err)
	}

	pid := cmd.Process.Pid

	// Detach: don't wait for the child. It will register itself with the daemon.
	go func() {
		if err := cmd.Wait(); err != nil {
			log.Debug("launcher: child %s (pid %d) exited: %v", tool, pid, err)
		}
	}()

	return pid, nil
}

// RestartSession kills an existing session and relaunches it with the same parameters.
func (l *Launcher) RestartSession(registry *Registry, id string, killFn func(string) error) (int, error) {
	inst := registry.Get(id)
	if inst == nil {
		return 0, fmt.Errorf("launcher: session %q not found", id)
	}

	snap := inst.Snapshot()

	// Kill the existing session.
	if err := killFn(id); err != nil {
		return 0, fmt.Errorf("launcher: kill %q: %w", id, err)
	}

	// Relaunch with the same parameters.
	return l.LaunchSession(snap.Tool, snap.Workdir, snap.Args)
}

// findDizginBinary locates the dizgin binary, checking next to the daemon first.
func findDizginBinary() string {
	name := brand.Name
	if runtime.GOOS == "windows" {
		name = brand.Name + ".exe"
	}

	// Check next to the current executable (dizgind).
	if exe, err := os.Executable(); err == nil {
		sibling := filepath.Join(filepath.Dir(exe), name)
		if _, err := os.Stat(sibling); err == nil {
			return sibling
		}
	}

	// Fall back to PATH.
	if p, err := exec.LookPath(name); err == nil {
		return p
	}

	return ""
}
