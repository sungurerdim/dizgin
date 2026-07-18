// SPDX-License-Identifier: MIT

//go:build !windows

package main

import (
	"os"

	"github.com/mattn/go-isatty"

	"github.com/sungurerdim/dizgin/internal/sandbox"
)

// setStampProgressCallback is a no-op on non-Windows builds — the
// stamp storm is a Windows AppContainer DACL phenomenon. Keeping the
// symbol available cross-platform lets the shared installStampProgress
// caller compile without build-tag fences.
func setStampProgressCallback(_ func(done, total int)) {}

// applyStampProgress is a no-op on non-Windows: the stamp-storm callback
// is never registered so there is nothing to wire into the backend.
func applyStampProgress(_ sandbox.Backend) {}

// isStderrTTY reports whether stderr is attached to a real terminal.
func isStderrTTY() bool {
	return isatty.IsTerminal(os.Stderr.Fd())
}
