// SPDX-License-Identifier: MIT

//go:build !windows

package daemon

// CleanupOrphanStagingDirs is a no-op outside Windows — orphan scratch-dir
// reaping for the restricted backend runs only on Windows.
func CleanupOrphanStagingDirs() {}

// StartStagingCleanupLoop returns a no-op stop function on non-Windows
// platforms. The signature is preserved so callers can share code between
// platforms.
func StartStagingCleanupLoop() (stop func()) { return func() {} }
