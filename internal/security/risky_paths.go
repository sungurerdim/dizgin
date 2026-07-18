// SPDX-License-Identifier: MIT

// Package security hosts security policy helpers that are shared across
// sandbox backends — notably the central deny-list for dynamic access
// learning. The list lives here rather than under cmd/dizgin so that other
// callers (daemon audit, future TUI confirmations) use the same SSOT.
package security

import (
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// RiskyReason explains why a path is denied. Callers surface the reason to
// the user (logs, audit rows) so they can see why an entry was blocked.
type RiskyReason string

const (
	RiskSystemSecurity   RiskyReason = "Windows registry hive / SECURITY store"
	RiskOtherUserProfile RiskyReason = "another user's profile"
	RiskSSHPrivateKey    RiskyReason = "SSH private key"
	RiskCredentialStore  RiskyReason = "OS credential / vault store" //nolint:gosec // G101 false positive: human-readable reason string, not a credential
	RiskBrowserSession   RiskyReason = "browser session / cookie store"
	RiskPasswordManager  RiskyReason = "password manager data"
	RiskRoamingProfile   RiskyReason = "Azure AD / roaming auth broker state"
	RiskCloudCreds       RiskyReason = "cloud provider credentials"
)

// riskyRule pairs a regex with a reason. The regex is anchored to the full
// cleaned path so prefix tricks like C:\Users\victim\..\admin cannot fool
// it — callers must clean via filepath.Clean before matching.
type riskyRule struct {
	re     *regexp.Regexp
	reason RiskyReason
}

var (
	defaultRulesOnce sync.Once
	defaultRules     []riskyRule
)

// defaultRiskyRules returns the built-in deny-list. All patterns are case
// insensitive — Windows filesystem is case insensitive so "C:\WINDOWS" and
// "c:\windows" must both match. Non-Windows callers get the same list;
// patterns that are unreachable on a given OS (e.g. C:\Windows\System32 on
// Linux) simply never match.
func defaultRiskyRules() []riskyRule {
	defaultRulesOnce.Do(func() {
		patterns := []struct {
			pat    string
			reason RiskyReason
		}{
			// Windows registry hives & SECURITY store.
			{`(?i)^[a-z]:\\windows\\system32\\config\\(sam|security|system|software|default|userdiff)(\..*)?$`, RiskSystemSecurity},
			{`(?i)^[a-z]:\\windows\\system32\\config\\regback(\\.*)?$`, RiskSystemSecurity},
			{`(?i)\\ntuser\.dat(\.log[0-9]*)?$`, RiskSystemSecurity},
			{`(?i)\\usrclass\.dat(\.log[0-9]*)?$`, RiskSystemSecurity},

			// SSH private keys — match *\.ssh\id_*, *\.ssh\*_rsa, *_ed25519, *_ecdsa, *_dsa.
			{`(?i)[\\/]\.ssh[\\/](id_[^\\/\.]+|[^\\/]*_(?:rsa|ed25519|ecdsa|dsa))$`, RiskSSHPrivateKey},
			{`(?i)[\\/]\.ssh[\\/]identity$`, RiskSSHPrivateKey},
			// SSH directory itself — used by `dizgin add-path` to refuse a
			// blanket mount that would expose every key file. Iter4
			// verify uncovered: a user typing `dizgin add-path ~/.ssh`
			// would have bypassed the per-file rules above.
			{`(?i)[\\/]\.ssh[\\/]?$`, RiskSSHPrivateKey},
			// Cloud credential directories — similar reasoning.
			{`(?i)[\\/]\.aws[\\/]?$`, RiskCloudCreds},
			{`(?i)[\\/]\.azure[\\/]?$`, RiskCloudCreds},
			{`(?i)[\\/]\.gcloud[\\/]?$`, RiskCloudCreds},
			{`(?i)[\\/]\.config[\\/]gcloud[\\/]?$`, RiskCloudCreds},

			// Cloud credentials.
			{`(?i)[\\/]\.aws[\\/]credentials$`, RiskCloudCreds},
			{`(?i)[\\/]\.config[\\/]gcloud[\\/](application_default_credentials\.json|legacy_credentials(\\.+)?)$`, RiskCloudCreds},
			{`(?i)[\\/]\.azure[\\/]accesstokens\.json$`, RiskCloudCreds},
			{`(?i)[\\/]\.azure[\\/]msal_token_cache(\..*)?$`, RiskCloudCreds},

			// GnuPG / Pass.
			{`(?i)[\\/]\.gnupg([\\/].*)?$`, RiskCredentialStore},
			{`(?i)[\\/]\.password-store([\\/].*)?$`, RiskPasswordManager},

			// Windows credential / vault stores.
			{`(?i)\\appdata\\local\\microsoft\\credentials([\\/].*)?$`, RiskCredentialStore},
			{`(?i)\\appdata\\roaming\\microsoft\\credentials([\\/].*)?$`, RiskCredentialStore},
			{`(?i)\\appdata\\local\\microsoft\\vault([\\/].*)?$`, RiskCredentialStore},
			{`(?i)\\appdata\\local\\microsoft\\protect([\\/].*)?$`, RiskCredentialStore},

			// Azure AD / AAD broker (roaming profile auth state).
			{`(?i)\\appdata\\local\\packages\\microsoft\.aad\.brokerplugin[^\\/]*([\\/].*)?$`, RiskRoamingProfile},
			{`(?i)\\appdata\\local\\packages\\microsoft\.accountscontrol[^\\/]*([\\/].*)?$`, RiskRoamingProfile},

			// Password managers.
			{`(?i)\.kdbx$`, RiskPasswordManager},
			{`(?i)[\\/]bitwarden[\\/]data\.json$`, RiskPasswordManager},
			{`(?i)[\\/]1password[^\\/]*[\\/].*\.opvault([\\/].*)?$`, RiskPasswordManager},
			{`(?i)[\\/]enpass([\\/].*)?\.walletx?$`, RiskPasswordManager},

			// Browser session / cookie stores.
			{`(?i)\\google\\chrome\\user data\\[^\\/]+\\cookies(-journal)?$`, RiskBrowserSession},
			{`(?i)\\microsoft\\edge\\user data\\[^\\/]+\\cookies(-journal)?$`, RiskBrowserSession},
			{`(?i)\\mozilla\\firefox\\profiles\\[^\\/]+\\cookies\.sqlite.*$`, RiskBrowserSession},
			{`(?i)\\brave-browser\\user data\\[^\\/]+\\cookies(-journal)?$`, RiskBrowserSession},
			{`(?i)\\google\\chrome\\user data\\[^\\/]+\\login data.*$`, RiskBrowserSession},
		}
		for _, p := range patterns {
			defaultRules = append(defaultRules, riskyRule{
				re:     regexp.MustCompile(p.pat),
				reason: p.reason,
			})
		}
	})
	return defaultRules
}

// IsRiskyPath reports whether a path matches the central deny-list. The
// check is the first filter dynamic access learning applies: matching paths
// never reach the user approval prompt and are never written to any profile.
//
// The caller must pass an absolute path — relative inputs are rejected
// (returns false) because relative paths cannot be reasoned about safely
// without a base directory. Callers that hold relative paths should resolve
// them with filepath.Abs first.
//
// Cross-platform note: Windows filepath.IsAbs rejects POSIX-style paths
// like "/home/alice/.ssh/id_rsa"; we accept those anyway because tools
// spawned inside the Windows sandbox may emit POSIX paths (MSYS2 bash)
// that we must still classify correctly.
func IsRiskyPath(p string) (bool, RiskyReason) {
	p = strings.TrimSpace(p)
	if p == "" {
		return false, ""
	}
	if !looksAbsolute(p) {
		return false, ""
	}
	cleaned := filepath.Clean(p)
	// Check against the central rule set.
	for _, r := range defaultRiskyRules() {
		if r.re.MatchString(cleaned) {
			return true, r.reason
		}
	}
	// Separate helper handles the cross-user-profile rule because it needs
	// the caller's own home directory to distinguish "my profile" from
	// "someone else's profile".
	if reason, ok := matchOtherUserProfile(cleaned); ok {
		return true, reason
	}
	return false, ""
}

// hasDriveLetter returns true for strings like "C:\foo" that filepath.IsAbs
// on non-Windows rejects. We want the rule table evaluated for those paths
// on all platforms — a Linux developer running integration tests against
// a recorded Windows path should still see the deny-list match.
func hasDriveLetter(p string) bool {
	return len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/')
}

// looksAbsolute tolerates cross-platform input. It accepts:
//   - Go's native IsAbs (host-native absolute paths)
//   - Windows drive-letter paths on any platform
//   - POSIX-rooted paths ("/home/...") on Windows — because MSYS2 bash
//     inside the sandbox emits them verbatim and we want the deny-list to
//     still classify those correctly.
func looksAbsolute(p string) bool {
	if filepath.IsAbs(p) {
		return true
	}
	if hasDriveLetter(p) {
		return true
	}
	if strings.HasPrefix(p, "/") {
		return true
	}
	return false
}

// matchOtherUserProfile returns true when p sits under C:\Users\<someone>
// but the someone is not the current process user. This is the "another
// user's profile" rule; it is too user-specific to embed in the regex table.
func matchOtherUserProfile(p string) (RiskyReason, bool) {
	// Windows-style: C:\Users\<name>\...
	re := regexp.MustCompile(`(?i)^([a-z]:\\users)\\([^\\]+)(\\.*)?$`)
	m := re.FindStringSubmatch(p)
	if m == nil {
		// Also cover POSIX-style homes under /Users (macOS) and /home (Linux).
		// These are less common in Windows-only DIZGIN but integration tests
		// may feed cross-platform paths through.
		re2 := regexp.MustCompile(`^(/Users|/home)/([^/]+)(/.*)?$`)
		m2 := re2.FindStringSubmatch(p)
		if m2 == nil {
			return "", false
		}
		if strings.EqualFold(m2[2], currentUserName()) {
			return "", false
		}
		// "Public" is the shared Windows profile; skip it.
		if strings.EqualFold(m2[2], "public") {
			return "", false
		}
		return RiskOtherUserProfile, true
	}
	name := m[2]
	if strings.EqualFold(name, currentUserName()) {
		return "", false
	}
	// Windows "Public" + "Default" + "All Users" are shared; tools that
	// legitimately need them are out-of-scope for DIZGIN's learn-and-replay
	// today, but excluding them from the deny-list avoids false positives
	// on legit system paths (e.g. C:\Users\Public\Documents\shared.sqlite).
	switch strings.ToLower(name) {
	case "public", "default", "default user", "all users":
		return "", false
	}
	return RiskOtherUserProfile, true
}

// currentUserName resolves the active username for the "other user profile"
// check. Implemented in platform files (risky_paths_windows.go /
// risky_paths_other.go) because Go's os/user drags in CGO on some
// platforms and we want the whole package to build without CGO.
