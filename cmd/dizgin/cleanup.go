// SPDX-License-Identifier: MIT

//go:build !windows

package main

import "github.com/sungurerdim/dizgin/internal/sandbox"

// runGlobalCleanup is a no-op. Kept for call-site clarity in main.go.
func runGlobalCleanup() {}

// registerBoxCleanup / unregisterBoxCleanup are no-ops.
// Container and Unix backends handle cleanup via --die-with-parent or defer.
func registerBoxCleanup(_ sandbox.Box) {}
func unregisterBoxCleanup()            {}
