// SPDX-License-Identifier: MIT

//go:build windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// kernel32 + FreeConsole proc, used by detachConsole() to break the
// daemon process off from whatever console window UAC opened when the
// installer (or `Start-Process -Verb RunAs dizgind start`) elevated us.
// Without this the elevated cmd window stays on screen for the entire
// daemon lifetime — visible nuisance, no functional purpose.
var (
	modKernel32  = syscall.NewLazyDLL("kernel32.dll")
	procFreeCons = modKernel32.NewProc("FreeConsole")
)

// redirectDaemonOutput tees the daemon's stdout + stderr to a per-boot
// banner-prefixed file under %ProgramData%\dizgin\logs\daemon.log AND
// detaches the process from its console so the elevated cmd window
// (opened by the UAC prompt) closes. Best effort: a failed redirect
// just means daemon.log misses this boot's output, which is non-fatal.
func redirectDaemonOutput() {
	progData := os.Getenv("ProgramData")
	if progData == "" {
		progData = `C:\ProgramData`
	}
	logDir := filepath.Join(progData, brand.Name, "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return
	}
	logFile := filepath.Join(logDir, "daemon.log")
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	banner := "\n=== dizgind daemon boot " + time.Now().Format(time.RFC3339Nano) +
		" (pid=" + itoa(os.Getpid()) + ") ===\n"
	_, _ = f.WriteString(banner)
	os.Stdout = f
	os.Stderr = f

	// Cut loose from the console AFTER stdio redirect so any output
	// emitted before this point still hit the host terminal (e.g. the
	// elevation prompt itself, install.ps1 progress lines). Once
	// FreeConsole returns, AllocConsole would be needed to attach a
	// new one — we don't, the daemon is now headless and writes only
	// to daemon.log.
	procFreeCons.Call() //nolint:errcheck
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
