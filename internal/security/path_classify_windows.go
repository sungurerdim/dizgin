// SPDX-License-Identifier: MIT

//go:build windows

package security

import (
	"os"
	"path/filepath"
	"strings"
)

// IsSystemPath reports whether host lives under one of the OS-managed
// directories (System32 / Program Files / ProgramData). Case-insensitive,
// separator-boundary prefix match so "C:\Windows-foo" does NOT match
// "C:\Windows".
//
// SSOT for the restricted backend's mount classifier (cmd/dizgin/mounts.go
// uses it to tag system PATH entries as CategorySystem vs CategoryPath
// for audit clarity) and the integrity-label denylist. The two used to
// maintain parallel literals that drifted over time (System32 was on
// one list but not the other, etc.); funnelling both through here keeps
// the system-root view consistent.
func IsSystemPath(host string) bool {
	if host == "" {
		return false
	}
	hostLower := strings.ToLower(filepath.Clean(host))
	sep := string(filepath.Separator)
	for _, c := range systemRoots() {
		if c == "" {
			continue
		}
		if hostLower == c || strings.HasPrefix(hostLower, c+sep) {
			return true
		}
	}
	return false
}

// IsVolumeRoot reports whether dir is a drive root like "C:\" or "D:\".
// Volume roots cannot be DACL-modified by a non-admin process and stamping
// them at all would propagate ACEs across an entire drive — always refuse.
func IsVolumeRoot(dir string) bool {
	clean := filepath.Clean(dir)
	vol := filepath.VolumeName(clean)
	if vol == "" {
		return false
	}
	return strings.EqualFold(clean, vol+`\`) || strings.EqualFold(clean, vol)
}

// IsIntegrityDenied reports whether dir is in the union of subtrees that
// must never receive a Low mandatory label ACE or an ancestor-traversal
// grant via an auto-walk. Returns (true, humanReason) on a denylist hit.
// Reasons:
//   - "volume root <path>"
//   - "matches denylist root <root>" (system dirs, user tool dirs, PATH dirs)
//   - "contains executable files" (defensive scan)
//
// The denylist exists because a prior R2-02 attempt blanket-applied Low IL
// to mounted dirs and propagated it via OI/CI inheritance into ~/.local/bin
// (binaries) and ~/.claude (32K config files). The check survives even
// after the auto-walk caller was deleted, as a belt-and-braces guard for
// any future caller that re-enables stamping.
func IsIntegrityDenied(dir string) (bool, string) {
	clean := filepath.Clean(dir)
	lower := strings.ToLower(clean)

	if IsVolumeRoot(clean) {
		return true, "volume root " + clean
	}

	sep := string(filepath.Separator)
	for _, deny := range integrityDenyDirs() {
		if deny == "" {
			continue
		}
		if lower == deny || strings.HasPrefix(lower, deny+sep) {
			return true, "matches denylist root " + deny
		}
	}

	if DirContainsExecutable(clean) {
		return true, "contains executable files"
	}
	return false, ""
}

// DirContainsExecutable reports whether dir has any *.exe / *.dll / *.bat /
// *.cmd / *.com / *.ps1 file (1-level scan, no recursion). Fail-closed on
// read errors (treat as containing executables) so a stamp call cannot
// silently relabel a dir we couldn't even list.
func DirContainsExecutable(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return true
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if strings.HasSuffix(name, ".exe") ||
			strings.HasSuffix(name, ".dll") ||
			strings.HasSuffix(name, ".bat") ||
			strings.HasSuffix(name, ".cmd") ||
			strings.HasSuffix(name, ".com") ||
			strings.HasSuffix(name, ".ps1") {
			return true
		}
	}
	return false
}

// systemRoots returns the lowercased, cleaned paths considered "system"
// — covered by the inbox ALL APPLICATION PACKAGES RX grant on every
// supported Windows build. Resolved lazily so test harnesses that
// re-export the env vars get the up-to-date list.
func systemRoots() []string {
	out := make([]string, 0, 8)
	add := func(s string) {
		if s != "" {
			out = append(out, strings.ToLower(filepath.Clean(s)))
		}
	}
	if v := os.Getenv("SystemRoot"); v != "" {
		add(v)
	} else {
		add(`C:\Windows`)
	}
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData"} {
		add(os.Getenv(env))
	}
	return out
}

// integrityDenyDirs is the union of fixed denylist roots. Wider than
// systemRoots because it also includes user tool directories (.local/bin,
// .cargo/bin, AppData\Roaming\npm, ~/.claude, ~/.ssh, etc.) and the
// machine's PATH entries. The 2026-05-17 incident showed that any
// ancestor-walk traversal grant that ignores this list propagates Low IL
// or RX into directories that hold 30K+ user files.
func integrityDenyDirs() []string {
	out := make([]string, 0, 32)
	add := func(s string) {
		if s != "" {
			out = append(out, strings.ToLower(filepath.Clean(s)))
		}
	}

	if v := os.Getenv("SystemRoot"); v != "" {
		add(v)
		add(filepath.Join(v, "System32"))
		add(filepath.Join(v, "SysWOW64"))
	}
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData"} {
		add(os.Getenv(env))
	}

	home := os.Getenv("USERPROFILE")
	if home == "" {
		home = os.Getenv("HOME")
	}
	if home != "" {
		// USERPROFILE root is NOT denied — per-session scratch dirs live
		// in AppData\Local\Temp and must remain stampable.
		for _, b := range []string{
			`.local\bin`,
			`.cargo\bin`,
			`go\bin`,
			`AppData\Local\Programs`,
			`AppData\Roaming\npm`,
			`AppData\Roaming\Microsoft\WindowsApps`,
			`AppData\Local\Microsoft\WindowsApps`,
			`bin`,
			`scoop`,
			`.claude`,
			`.gemini`,
			`.codex`,
			`.cursor`,
			`.config`,
			`.ssh`,
		} {
			add(filepath.Join(home, b))
		}
	}

	// PATH entries — except entries that resolve under %TEMP%/%TMP%.
	// Per-session scratch dirs live in Temp and must remain stampable.
	tempRoots := []string{}
	for _, e := range []string{"TEMP", "TMP"} {
		if v := os.Getenv(e); v != "" {
			tempRoots = append(tempRoots, strings.ToLower(filepath.Clean(v)))
		}
	}
	underTemp := func(p string) bool {
		lp := strings.ToLower(filepath.Clean(p))
		for _, t := range tempRoots {
			if lp == t || strings.HasPrefix(lp, t+string(filepath.Separator)) {
				return true
			}
		}
		return false
	}
	if pathEnv := os.Getenv("PATH"); pathEnv != "" {
		for _, p := range strings.Split(pathEnv, string(os.PathListSeparator)) {
			if p == "" || underTemp(p) {
				continue
			}
			add(p)
		}
	}
	return out
}
