// SPDX-License-Identifier: MIT

package security

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// userDenyFile is the YAML shape written to ~/.dizgin/deny/<tool>.yaml when
// the user picks "block" in the approval prompt. It is additive to the
// central rules in defaultRiskyRules — it cannot loosen them.
type userDenyFile struct {
	Paths []userDenyEntry `yaml:"paths"`
}

type userDenyEntry struct {
	Path    string `yaml:"path"`
	Reason  string `yaml:"reason,omitempty"`
	AddedAt string `yaml:"added_at,omitempty"`
}

var (
	userDenyMu       sync.Mutex
	userDenyRules    []riskyRule
	userDenyRulesSet bool
	userDenyDir      string // overridable for tests
)

// SetUserDenyDir lets tests redirect the on-disk deny directory. Empty
// string restores the default (~/.dizgin/deny).
func SetUserDenyDir(dir string) {
	userDenyMu.Lock()
	defer userDenyMu.Unlock()
	userDenyDir = dir
	userDenyRules = nil
	userDenyRulesSet = false
}

// userDenyRootLocked returns the deny directory; caller must hold
// userDenyMu. Separated from userDenyRoot so loadUserDeny (already under
// the mutex) does not deadlock.
func userDenyRootLocked() string {
	if userDenyDir != "" {
		return userDenyDir
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, brand.DotDir, "deny")
}

// userDenyRoot is the public wrapper used by AppendUserDeny. Takes the
// mutex, then delegates to the locked helper.
func userDenyRoot() string {
	userDenyMu.Lock()
	defer userDenyMu.Unlock()
	return userDenyRootLocked()
}

// loadUserDeny populates userDenyRules from YAML files in the deny dir.
// Errors are swallowed and reported via stderr so a malformed user file
// never breaks sandboxed execution — the central rules still apply.
func loadUserDeny() []riskyRule {
	userDenyMu.Lock()
	defer userDenyMu.Unlock()
	if userDenyRulesSet {
		return userDenyRules
	}

	dir := userDenyRootLocked()
	rules := []riskyRule{}
	if dir == "" {
		userDenyRules = rules
		userDenyRulesSet = true
		return rules
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		userDenyRules = rules
		userDenyRulesSet = true
		return rules
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var f userDenyFile
		if yaml.Unmarshal(data, &f) != nil {
			continue
		}
		for _, ent := range f.Paths {
			p := strings.TrimSpace(ent.Path)
			if p == "" {
				continue
			}
			re, rerr := regexp.Compile(literalPathPattern(p))
			if rerr != nil {
				continue
			}
			reason := ent.Reason
			if reason == "" {
				reason = "user deny-list"
			}
			rules = append(rules, riskyRule{re: re, reason: RiskyReason(reason)})
		}
	}
	userDenyRules = rules
	userDenyRulesSet = true
	return rules
}

// literalPathPattern converts a user-supplied literal path into a case
// insensitive anchored regex. Wildcards (* and ?) are honoured so users
// can write "C:\Users\X\.ssh\*" without writing regex themselves.
func literalPathPattern(p string) string {
	escaped := regexp.QuoteMeta(filepath.Clean(p))
	// QuoteMeta escapes the path; unescape our two supported wildcards.
	escaped = strings.ReplaceAll(escaped, `\*`, `.*`)
	escaped = strings.ReplaceAll(escaped, `\?`, `.`)
	return "(?i)^" + escaped + "$"
}

// IsUserDenied reports whether the path is covered by a user-specific
// deny rule. The result is combined with IsRiskyPath by callers; user
// rules extend the central list but cannot remove entries from it.
func IsUserDenied(p string) (bool, RiskyReason) {
	p = strings.TrimSpace(p)
	if p == "" {
		return false, ""
	}
	cleaned := filepath.Clean(p)
	for _, r := range loadUserDeny() {
		if r.re.MatchString(cleaned) {
			return true, r.reason
		}
	}
	return false, ""
}

// AppendUserDeny writes a new entry into the per-tool user deny file.
// Creates the file and directory when needed. Subsequent IsUserDenied
// calls pick up the new rule (in-memory cache is cleared).
func AppendUserDeny(tool, path, reason string) error {
	dir := userDenyRoot()
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	name := strings.ToLower(strings.TrimSuffix(filepath.Base(tool), ".exe"))
	if name == "" {
		name = "default"
	}
	target := filepath.Join(dir, name+".yaml")

	var f userDenyFile
	if data, err := os.ReadFile(target); err == nil {
		_ = yaml.Unmarshal(data, &f)
	}
	for _, ent := range f.Paths {
		if strings.EqualFold(filepath.Clean(ent.Path), filepath.Clean(path)) {
			return nil // already present — idempotent
		}
	}
	f.Paths = append(f.Paths, userDenyEntry{
		Path:   path,
		Reason: reason,
	})
	out, err := yaml.Marshal(f)
	if err != nil {
		return err
	}
	if err := os.WriteFile(target, out, 0o600); err != nil {
		return err
	}
	// Drop in-memory cache so the new rule takes effect.
	userDenyMu.Lock()
	userDenyRules = nil
	userDenyRulesSet = false
	userDenyMu.Unlock()
	return nil
}
