// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/security"
)

// Zero-config auto-grant (plan Phase 4c).
//
// On a NORMAL run (no --learn), dizgin still records access-denial lines via
// the same accessRecorder. At exit, the denied paths are auto-classified:
//
//   - Non-sensitive path → auto-grant READ-ONLY. RO can never let the tool
//     modify anything, and the path is outside the credential SSOT, so
//     granting it is safe to do without asking. Persisted to
//     ~/.dizgin/permissions/<tool>.yaml so the next run just works.
//   - Sensitive path (security.IsSensitiveDeny) → NEVER auto-granted. On a
//     TTY the user is prompted (the existing --learn prompt, scoped to the
//     sensitive subset); off a TTY it is skipped with a clear summary.
//
// Invariants (security-critical):
//   - R1 is never auto-relaxed: a sensitive-SSOT path is never written to
//     the profile without an explicit interactive decision.
//   - RW is never auto-granted: the automatic path only ever adds RO.
//
// Escape hatch: DIZGIN_NO_AUTO_GRANT=1 disables the whole mechanism (the
// recorder is then only created for explicit --learn).

// autoGrantEnabled reports whether the zero-config auto-grant path is
// active. Mirrors the env-switch pattern of the other layers.
func autoGrantEnabled() bool {
	return os.Getenv(brand.Env("NO_AUTO_GRANT")) != "1"
}

// autoGrantSafe reports whether a denied path may be auto-granted RO
// without asking. The single hard rule: anything in the credential SSOT
// is NOT safe (must stay an explicit decision). Everything else — system
// dirs, non-sensitive user files — is safe for a read-only grant.
func autoGrantSafe(path string) bool {
	return !security.IsSensitiveDeny(path)
}

// splitDeniedPaths partitions recorded denial paths into the safe set
// (auto-RO eligible) and the sensitive set (needs an explicit decision).
func splitDeniedPaths(paths []string) (safe, sensitive []string) {
	for _, p := range paths {
		if autoGrantSafe(p) {
			safe = append(safe, p)
		} else {
			sensitive = append(sensitive, p)
		}
	}
	return safe, sensitive
}

// overridesContainFold reports whether path is already covered by any of
// the RW/RO/Deny lists (case-insensitive, cleaned). Prevents re-adding a
// path the user already classified.
func overridesContainFold(o Overrides, path string) bool {
	want := strings.ToLower(filepath.Clean(path))
	for _, list := range [][]string{o.RW, o.RO, o.Deny} {
		for _, e := range list {
			if strings.ToLower(filepath.Clean(e)) == want {
				return true
			}
		}
	}
	return false
}

// maybeAutoGrantPermissions runs the 4c flow at session exit on a normal
// (non-learn) run. Best-effort: every failure path degrades to "do
// nothing" so the tool's own exit is never disturbed.
func (b *box) maybeAutoGrantPermissions() {
	if b.recorder == nil || b.opts.ToolName == "" {
		return
	}
	paths := b.recorder.PathHits()
	if len(paths) == 0 {
		return
	}
	safe, sensitive := splitDeniedPaths(paths)

	existing := FromSandboxOverrides(b.opts.PermissionOverrides)
	updated := existing
	changed := false

	// Auto-grant RO for every non-sensitive denied path not already known.
	var granted []string
	for _, p := range safe {
		if overridesContainFold(updated, p) {
			continue
		}
		updated.RO = append(updated.RO, p)
		granted = append(granted, p)
		changed = true
	}

	// Sensitive paths: never auto. Prompt on a TTY, summarise + skip otherwise.
	if len(sensitive) > 0 {
		if isStdinTTY() {
			fmt.Fprintf(os.Stderr, brand.Name+": %d sensitive path(s) were denied — review (auto-grant never touches these):\n", len(sensitive))
			updated = PromptForPermissions(os.Stderr, os.Stdin, sensitive, updated)
			if !overridesEqual(existing, updated) {
				changed = true
			}
		} else {
			fmt.Fprintf(os.Stderr, brand.Name+": %d sensitive path(s) denied and NOT auto-granted (run `dizgin --learn` to review): %s\n",
				len(sensitive), strings.Join(sensitive, ", "))
		}
	}

	if !changed {
		return
	}

	profile := &PermissionProfile{
		Version:   permissionsSchemaVersion,
		ToolName:  b.opts.ToolName,
		ToolPath:  b.opts.ToolPath,
		Overrides: updated,
	}
	if err := SavePermissionProfile(profile); err != nil {
		fmt.Fprintf(os.Stderr, brand.Name+": auto-grant: save permissions: %v\n", err)
		return
	}
	if len(granted) > 0 {
		fmt.Fprintf(os.Stderr, brand.Name+": auto-granted read-only access to %d path(s) for %q (next run will not re-prompt; set DIZGIN_NO_AUTO_GRANT=1 to disable): %s\n",
			len(granted), b.opts.ToolName, strings.Join(granted, ", "))
	}
}
