// SPDX-License-Identifier: MIT

//go:build windows

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

// currentUserName reads USERNAME, falling back to the final segment of
// USERPROFILE when USERNAME is empty (seen on some service contexts).
// The lookup is memoised — the answer never changes mid-process.
func currentUserName() string {
	currentUserNameMu.Lock()
	defer currentUserNameMu.Unlock()
	if currentUserNameSet {
		return currentUserNameCache
	}
	currentUserNameCache = resolveCurrentUserWindows()
	currentUserNameSet = true
	return currentUserNameCache
}

func resolveCurrentUserWindows() string {
	if u := strings.TrimSpace(os.Getenv("USERNAME")); u != "" {
		return u
	}
	if p := os.Getenv("USERPROFILE"); p != "" {
		for i := len(p) - 1; i >= 0; i-- {
			if p[i] == '\\' || p[i] == '/' {
				return p[i+1:]
			}
		}
		return p
	}
	return ""
}

// resetCurrentUserCache clears the memoised username. Tests use this after
// Setenv to force a fresh lookup. Not exported — lives in the package so
// callers cannot accidentally churn the cache at runtime.
func resetCurrentUserCache() {
	currentUserNameMu.Lock()
	defer currentUserNameMu.Unlock()
	currentUserNameSet = false
	currentUserNameCache = ""
}
