// SPDX-License-Identifier: MIT

//go:build windows

// Package restricted — per-session scratch tree allocation.
//
// Mirrors the iter5 AppContainer scratch layout (now deleted): the
// restricted backend keeps its own subdirectory under the shared
// scratch roots so the daemon orphan-sweeper can find sessions by
// glob without cross-backend reaping. Kept independent of any
// hypothetical future backend for the same reason.
package restricted

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// ScratchRoots returns the candidate roots dizgin will try when carving
// a per-session restricted-backend scratch tree. Order matters:
// ProgramData first (preferred — survives reboot, admin-owned when
// dizgind setup is wired), LOCALAPPDATA second (fallback for non-
// elevated dizgin processes).
func ScratchRoots() []string {
	roots := []string{`C:\ProgramData\dizgin\restricted`}
	if lad := os.Getenv("LOCALAPPDATA"); lad != "" {
		roots = append(roots, filepath.Join(lad, brand.Name, "restricted"))
	}
	return roots
}

// SessionScratchDir creates and returns the per-session scratch
// directory for sessionID. Tries each ScratchRoots() candidate until
// one accepts the mkdir; returns an error listing the tried set when
// none worked.
func SessionScratchDir(sessionID string) (string, error) {
	candidates := ScratchRoots()
	for _, root := range candidates {
		if err := os.MkdirAll(root, 0o755); err != nil {
			continue
		}
		full := filepath.Join(root, sessionID)
		if err := os.MkdirAll(full, 0o755); err == nil {
			return full, nil
		}
	}
	return "", fmt.Errorf("restricted: no writable scratch root (tried %v)", candidates)
}
