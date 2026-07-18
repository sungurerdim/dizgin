// SPDX-License-Identifier: MIT

//go:build windows

package main

import (
	"os"

	"github.com/mattn/go-isatty"

	"github.com/sungurerdim/dizgin/internal/sandbox"
)

// pendingStampProgressCb is the callback registered by installStampProgress
// before the backend is resolved. applyStampProgress wires it into the
// backend via the StampProgressSetter optional interface once the backend
// is available (inside createSandbox, after sandbox.Get). This decouples
// cmd/dizgin from the concrete restricted package (ARC-04): only the
// sandbox.StampProgressSetter interface is imported here, never the
// implementation.
var pendingStampProgressCb func(done, total int)

// setStampProgressCallback stores cb for later wiring. The actual wiring
// into the backend happens in applyStampProgress, called from createSandbox
// after the backend is resolved.
func setStampProgressCallback(cb func(done, total int)) {
	pendingStampProgressCb = cb
}

// applyStampProgress wires the stored callback into backend via the
// StampProgressSetter optional interface. Called from createSandbox once
// backend is resolved. No-op if no callback was registered or the backend
// does not implement the interface.
func applyStampProgress(b sandbox.Backend) {
	if pendingStampProgressCb == nil {
		return
	}
	if setter, ok := b.(sandbox.StampProgressSetter); ok {
		setter.SetStampProgress(pendingStampProgressCb)
	}
}

// isStderrTTY reports whether stderr is attached to a real terminal.
// Used by the stamp progress renderer to choose between in-place
// updates and plain log lines.
func isStderrTTY() bool {
	return isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd())
}
