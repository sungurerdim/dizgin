// SPDX-License-Identifier: MIT

//go:build !windows

package audit

import (
	"os"
	"path/filepath"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// logFilePath returns the platform-specific audit log path.
// Unix: ~/.local/share/dizgin/audit.jsonl
func logFilePath() (string, error) {
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, brand.Name, "audit.jsonl"), nil
}
