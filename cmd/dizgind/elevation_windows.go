// SPDX-License-Identifier: MIT

//go:build windows

package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/daemon"
)

// waitDaemonReadyAndReport polls daemon.IsDaemonRunning for up to 5s
// after spawning the elevated child and prints a single line so the
// user knows whether `dizgind start` succeeded. Without this the
// pre-elevation parent would exit silently — the elevated child's
// stderr is attached to a hidden console and never reaches the caller.
//
// Polling cadence is 100ms × 50 = 5s budget. The same pattern is what
// the dizgin wrapper uses when it auto-launches the daemon via
// `dizgin: starting dizgind daemon...`.
func waitDaemonReadyAndReport() {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if daemon.IsDaemonRunning() {
			fmt.Fprintln(os.Stderr, brand.DaemonName+": daemon started")
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Fprintln(os.Stderr, brand.DaemonName+": daemon failed to start within 5s — check %ProgramData%\\dizgin\\logs")
}

type tokenElevation struct {
	TokenIsElevated uint32
}

func isElevated() bool {
	const tokenElevationClass = 20
	token := windows.GetCurrentProcessToken()
	var elev tokenElevation
	n := uint32(unsafe.Sizeof(elev))
	if err := windows.GetTokenInformation(token, tokenElevationClass, (*byte)(unsafe.Pointer(&elev)), n, &n); err != nil {
		return false
	}
	return elev.TokenIsElevated != 0
}

const (
	seeMaskNoCloseProcess = 0x00000040
	seeMaskNoConsole      = 0x00008000
	swHide                = 0
	swShowNormal          = 1
)

// shellExecInfo mirrors the SHELLEXECUTEINFOW layout used by ShellExecuteExW.
// The cbSize field must be 112 (the W variant on 64-bit Windows).
type shellExecInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         uintptr
	lpVerb       uintptr
	lpFile       uintptr
	lpParameters uintptr
	lpDirectory  uintptr
	nShow        int32
	_pad         int32
	hInstApp     uintptr
	lpIDList     uintptr
	lpClass      uintptr
	hkeyClass    uintptr
	dwHotKey     uint32
	_pad2        uint32
	hMonitor     uintptr
	hProcess     uintptr
}

// buildShellExecInfo fills a shellExecInfo for a "runas" re-launch of exe
// with the given params string. detach selects hidden-window mode.
func buildShellExecInfo(exe, params string, detach bool) (shellExecInfo, *uint16, *uint16, *uint16) {
	verbPtr, _ := syscall.UTF16PtrFromString("runas")
	filePtr, _ := syscall.UTF16PtrFromString(exe)
	paramsPtr, _ := syscall.UTF16PtrFromString(params)

	var sei shellExecInfo
	sei.cbSize = 112
	sei.lpVerb = uintptr(unsafe.Pointer(verbPtr))
	sei.lpFile = uintptr(unsafe.Pointer(filePtr))
	sei.lpParameters = uintptr(unsafe.Pointer(paramsPtr))
	if detach {
		// Background daemon: hide window, suppress console creation.
		sei.fMask = seeMaskNoCloseProcess | seeMaskNoConsole
		sei.nShow = swHide
	} else {
		// Interactive (TUI or foreground start): show window normally.
		sei.fMask = seeMaskNoCloseProcess
		sei.nShow = swShowNormal
	}
	// Return the UTF-16 pointers so their memory stays alive until ShellExecuteExW returns.
	return sei, verbPtr, filePtr, paramsPtr
}

// waitAndMirrorExit waits for the process identified by hProcess to exit and
// calls os.Exit with its exit code. The handle is closed before returning.
func waitAndMirrorExit(hProcess uintptr) {
	h := syscall.Handle(hProcess)
	_, _ = syscall.WaitForSingleObject(h, syscall.INFINITE)
	var code uint32
	_ = syscall.GetExitCodeProcess(h, &code)
	_ = syscall.CloseHandle(h)
	os.Exit(int(code))
}

// ensureElevated re-launches dizgind with admin privileges if not already elevated.
// In detach mode (--detach flag): the elevated process is launched with a hidden
// console window (SW_HIDE + SEE_MASK_NO_CONSOLE) and the caller exits immediately
// without waiting, so no terminal window remains visible.
func ensureElevated() {
	if isElevated() {
		return
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, brand.DaemonName+": cannot resolve executable:", err)
		os.Exit(1)
	}

	params := strings.Join(os.Args[1:], " ")
	sei, _, _, _ := buildShellExecInfo(exe, params, detachMode)

	shell32 := syscall.NewLazyDLL("shell32.dll")
	shellExec := shell32.NewProc("ShellExecuteExW")

	ret, _, callErr := shellExec.Call(uintptr(unsafe.Pointer(&sei)))
	if ret == 0 {
		fmt.Fprintf(os.Stderr, brand.DaemonName+": elevation failed: %v\n", callErr)
		os.Exit(1)
	}

	if detachMode {
		// Fire-and-forget: elevated daemon is running hidden. Before
		// exiting, poll IsDaemonRunning so the user gets an unambiguous
		// "started" / "failed to start" line — the elevated child writes
		// to a hidden console that never reaches stderr here.
		_ = syscall.CloseHandle(syscall.Handle(sei.hProcess))
		waitDaemonReadyAndReport()
		os.Exit(0)
	}

	// Interactive: wait for the elevated process to exit and mirror its code.
	waitAndMirrorExit(sei.hProcess)
}
