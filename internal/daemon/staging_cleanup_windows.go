// SPDX-License-Identifier: MIT

//go:build windows

package daemon

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/log"
	"github.com/sungurerdim/dizgin/internal/sandbox/restricted"
)

// stagingOrphanMaxAge is the grace window before a seemingly-dead staging
// dir is removed. Keeps concurrent dizgin sessions running outside the PID
// check from losing their own staging trees to a race where OpenProcess
// transiently fails.
const stagingOrphanMaxAge = 10 * time.Minute

// stagingCleanupInterval is how often the daemon re-runs the sweep. Hourly
// is frequent enough to keep disk use tidy without generating noisy IO.
const stagingCleanupInterval = time.Hour

// CleanupOrphanStagingDirs reaps orphan scratch dirs left behind by crashed
// dizgin processes. It sweeps the restricted-backend scratch roots returned by
// restricted.ScratchRoots() (C:\ProgramData\dizgin\restricted and the
// LOCALAPPDATA fallback). A directory is removed only when its owner PID is
// no longer alive AND its mtime exceeds stagingOrphanMaxAge. Directory names
// that don't match the "dizgin-<pid>-<nano>" shape are left alone.
//
// No userenv profile reap is needed — the restricted backend registers no
// OS-managed profile; only the scratch dir + DACL DENY stamps need cleanup,
// and Box.Cleanup handles the stamps on the success path.
//
// Errors are logged at debug level and never propagated: dizgind must not
// crash because a cleanup sweep failed.
func CleanupOrphanStagingDirs() {
	for _, root := range restricted.ScratchRoots() {
		cleanupRestrictedRoot(root)
	}
}

// cleanupRestrictedRoot reaps per-session scratch dirs left behind
// when a dizgin process crashed before Cleanup ran. Session dirs share
// the "dizgin-<pid>-<nano>" shape so parseStagingSessionID still
// works after stripping the prefix.
func cleanupRestrictedRoot(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if !os.IsNotExist(err) {
			log.DebugSub(log.SubContainer, "restricted-cleanup: read %s: %v", root, err)
		}
		return
	}
	removed := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		pidPart := strings.TrimPrefix(name, brand.Name+"-")
		if pidPart == name {
			continue
		}
		pid, ok := parseStagingSessionID(pidPart)
		if !ok {
			continue
		}
		if isProcessAlive(pid) {
			continue
		}
		full := filepath.Join(root, name)
		info, err := e.Info()
		if err != nil {
			log.DebugSub(log.SubContainer, "restricted-cleanup: stat %s: %v", full, err)
			continue
		}
		if time.Since(info.ModTime()) < stagingOrphanMaxAge {
			continue
		}
		if err := os.RemoveAll(full); err != nil {
			log.DebugSub(log.SubContainer, "restricted-cleanup: remove %s: %v", full, err)
			continue
		}
		removed++
	}
	if removed > 0 {
		log.Info("restricted-cleanup: removed %d orphan scratch dir(s) under %s", removed, root)
	}
}

// cleanupStagingRoot sweeps root for orphan "<pid>-<nano>" subdirs whose
// owner PID is dead and mtime exceeds stagingOrphanMaxAge. Used by tests
// to exercise the shared parseStagingSessionID + isProcessAlive logic
// against an arbitrary temp directory.
func cleanupStagingRoot(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if !os.IsNotExist(err) {
			log.DebugSub(log.SubContainer, "staging-cleanup: read %s: %v", root, err)
		}
		return
	}
	removed := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, ok := parseStagingSessionID(e.Name())
		if !ok {
			continue
		}
		if isProcessAlive(pid) {
			continue
		}
		full := filepath.Join(root, e.Name())
		info, err := e.Info()
		if err != nil {
			log.DebugSub(log.SubContainer, "staging-cleanup: stat %s: %v", full, err)
			continue
		}
		if time.Since(info.ModTime()) < stagingOrphanMaxAge {
			continue
		}
		if err := os.RemoveAll(full); err != nil {
			log.DebugSub(log.SubContainer, "staging-cleanup: remove %s: %v", full, err)
			continue
		}
		removed++
	}
	if removed > 0 {
		log.Info("staging-cleanup: removed %d orphan dir(s) under %s", removed, root)
	}
}

// parseStagingSessionID extracts the PID from a "<pid>-<nano>" directory
// name. Returns 0 and false when the name does not match the expected
// format.
func parseStagingSessionID(name string) (int, bool) {
	idx := strings.IndexByte(name, '-')
	if idx <= 0 {
		return 0, false
	}
	pid, err := strconv.Atoi(name[:idx])
	if err != nil || pid <= 0 {
		return 0, false
	}
	// The suffix must be all-digit (nano timestamp); fail closed otherwise
	// so unrelated dirs never get removed.
	for _, c := range name[idx+1:] {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	return pid, true
}

// isProcessAlive opens the process for limited query access. A successful
// open proves the PID still refers to a running process; anything else
// means we should treat it as dead. PID reuse is unlikely to false-positive
// here because the mtime filter (10 min) also has to pass.
func isProcessAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h) //nolint:errcheck

	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	const stillActive = 259 // STILL_ACTIVE
	return code == stillActive
}

// StartStagingCleanupLoop kicks off a periodic cleanup sweep that runs until
// the returned stop function is called. The first sweep runs immediately so
// dizgind startup clears any trees left behind by crashed dizgin invocations.
func StartStagingCleanupLoop() (stop func()) {
	CleanupOrphanStagingDirs()

	stopCh := make(chan struct{})
	var once sync.Once
	go func() {
		ticker := time.NewTicker(stagingCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				CleanupOrphanStagingDirs()
			}
		}
	}()
	return func() { once.Do(func() { close(stopCh) }) }
}
