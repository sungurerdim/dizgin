// SPDX-License-Identifier: MIT

//go:build !windows

package security

import (
	"os"
	"strings"
	"sync"
)

var (
	currentUserNameMu    sync.Mutex
	currentUserNameCache string
	currentUserNameSet   bool
)

// currentUserName resolves the active username by reading USER / LOGNAME
// before falling back to HOME's final segment. Memoised because the
// result is stable for the life of the process.
func currentUserName() string {
	currentUserNameMu.Lock()
	defer currentUserNameMu.Unlock()
	if currentUserNameSet {
		return currentUserNameCache
	}
	currentUserNameCache = resolveCurrentUserPosix()
	currentUserNameSet = true
	return currentUserNameCache
}

func resolveCurrentUserPosix() string {
	if u := strings.TrimSpace(os.Getenv("USER")); u != "" {
		return u
	}
	if u := strings.TrimSpace(os.Getenv("LOGNAME")); u != "" {
		return u
	}
	if home := os.Getenv("HOME"); home != "" {
		for i := len(home) - 1; i >= 0; i-- {
			if home[i] == '/' {
				return home[i+1:]
			}
		}
		return home
	}
	return ""
}

// resetCurrentUserCache clears the memoised username. Tests use this after
// Setenv to force a fresh lookup.
func resetCurrentUserCache() {
	currentUserNameMu.Lock()
	defer currentUserNameMu.Unlock()
	currentUserNameSet = false
	currentUserNameCache = ""
}
