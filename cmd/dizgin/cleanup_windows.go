// SPDX-License-Identifier: MIT

//go:build windows

package main

import "github.com/sungurerdim/dizgin/internal/sandbox"

// runGlobalCleanup is a no-op under the AppContainer backend. The Job
// Object created in box.Start carries KILL_ON_JOB_CLOSE, so closing the
// job handle in box.Cleanup tears down every descendant process. The
// per-mount AC SID grants are revoked there too. There is nothing left
// for a global cleanup hook to do.
func runGlobalCleanup() {}

// registerBoxCleanup / unregisterBoxCleanup are no-ops. Box.Cleanup is
// called via defer in main.go::run; no panic-recovery box tracking is
// needed because the Job Object handles the abort case.
func registerBoxCleanup(_ sandbox.Box) {}
func unregisterBoxCleanup()            {}
