// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// Interactive --learn persistence + override-comparison helpers.
// Extracted from box_windows.go (behaviour-preserving move) to keep the
// Box implementation file under the 500-line quality threshold.

// maybePromptAndSavePermissions runs the iter6 Phase D interactive
// flow at session exit: if the recorder captured any extractable
// paths AND we have a stable tool name to key against, present the
// prompt to the user and persist their decisions to
// ~/.dizgin/permissions/<tool>.yaml.
//
// Defensive no-ops protect every failure mode that should not
// degrade the user's primary flow (the tool already exited):
//   - No paths captured → nothing to ask.
//   - opts.ToolName empty → cannot key the file safely.
//   - PromptForPermissions internally degrades to skip on non-TTY,
//     returning the existing overrides unchanged — in which case we
//     also skip the save (no decision means no file write).
//   - Save errors are reported to stderr but never propagated.
func (b *box) maybePromptAndSavePermissions() {
	if b.recorder == nil || b.opts.ToolName == "" {
		return
	}
	paths := b.recorder.PathHits()
	if len(paths) == 0 {
		return
	}
	existing := FromSandboxOverrides(b.opts.PermissionOverrides)
	updated := PromptForPermissions(os.Stderr, os.Stdin, paths, existing)

	// Skip the write when nothing changed — non-TTY environments hit
	// this path automatically (PromptForPermissions returns existing
	// untouched), and re-running --learn from a piped shell shouldn't
	// truncate the LearnedAt timestamp on disk.
	if overridesEqual(existing, updated) {
		fmt.Fprintln(os.Stderr, brand.Name+": no permission decisions recorded; ~/.dizgin/permissions/"+
			b.opts.ToolName+".yaml left unchanged")
		return
	}

	profile := &PermissionProfile{
		Version:   permissionsSchemaVersion,
		ToolName:  b.opts.ToolName,
		ToolPath:  b.opts.ToolPath,
		LearnedAt: time.Now().UTC(),
		Overrides: updated,
	}
	if err := SavePermissionProfile(profile); err != nil {
		fmt.Fprintf(os.Stderr, brand.Name+": save permissions: %v\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, brand.Name+": saved %d permission decision(s) to ~/.dizgin/permissions/%s.yaml\n",
		len(updated.RW)+len(updated.RO)+len(updated.Deny), b.opts.ToolName)
}

// overridesEqual compares two Overrides for set equality across the
// three slices. Cheap because canonical paths are already lowercased
// + cleaned — a plain string compare in sorted order is enough.
func overridesEqual(a, b Overrides) bool {
	return slicesEqualFold(a.RW, b.RW) &&
		slicesEqualFold(a.RO, b.RO) &&
		slicesEqualFold(a.Deny, b.Deny)
}

// slicesEqualFold reports set equality (order-insensitive) under case-
// insensitive comparison. Both slices are canonical-form so a direct
// EqualFold suffices.
func slicesEqualFold(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	used := make([]bool, len(b))
	for _, av := range a {
		matched := false
		for i, bv := range b {
			if used[i] {
				continue
			}
			if strings.EqualFold(av, bv) {
				used[i] = true
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}
