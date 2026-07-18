// SPDX-License-Identifier: MIT

//go:build windows

package audit

import (
	"os"
	"path/filepath"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// logFilePath returns the platform-specific audit log path.
// Windows: %LOCALAPPDATA%\dizgin.audit.jsonl
func logFilePath() (string, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, "AppData", "Local")
	}
	return filepath.Join(base, brand.Name, "audit.jsonl"), nil
}
