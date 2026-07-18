// SPDX-License-Identifier: MIT

// Package platform detects the current OS and maps it to a sandbox backend name.
//
// Dependency direction: sandbox/* sub-packages may import platform (for OS
// utilities like SetupContainerDone, ApplyRlimits), but platform must NOT import
// any sandbox/* sub-package to avoid a bidirectional cycle. Importing the parent
// sandbox package (which has no transitive dependency on platform) is safe and
// allows BackendForOS to reference the canonical BackendName* constants from
// sandbox/names.go rather than duplicating string literals here.
package platform

import (
	"fmt"
	"runtime"

	"github.com/sungurerdim/dizgin/internal/sandbox"
)

// BackendName returns the canonical sandbox backend name for the
// current OS. iter6 ships restricted as the sole Windows backend;
// the DIZGIN_BACKEND override that lived here during Phase 3 was
// retired in Phase 4 when the AppContainer package was deleted.
//
// Returns an error on unsupported platforms.
func BackendName() (string, error) {
	return BackendForOS(runtime.GOOS)
}

// BackendForOS maps a GOOS string to the canonical sandbox backend name.
// Exposed separately so tests can pin a GOOS without exporting env state.
// Uses sandbox.BackendName* constants as the SSOT to prevent silent
// rename desync between detect.go and each backend's Name() method.
func BackendForOS(goos string) (string, error) {
	switch goos {
	case "windows":
		// Sole Windows backend: restricted token + Medium IL + Job + DACL DENY.
		return sandbox.BackendNameRestricted, nil
	case "darwin":
		return sandbox.BackendNameSeatbelt, nil
	case "linux":
		return sandbox.BackendNameBubblewrap, nil
	default:
		return "", fmt.Errorf("platform: unsupported OS %q", goos)
	}
}
