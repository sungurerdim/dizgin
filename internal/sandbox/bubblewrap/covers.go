// SPDX-License-Identifier: MIT

package bubblewrap

import (
	"path/filepath"
	"strings"

	"github.com/sungurerdim/dizgin/internal/sandbox"
)

// This file holds the platform-neutral decision logic for R1 sensitive-path
// cover mounts, kept tag-free so it is unit-testable on any OS (the bwrap
// argument emission that consumes it lives in the linux-tagged backend).

// coverCandidates returns the sensitive paths that need shadowing inside the
// sandbox: those that fall under a requested mount (so they would otherwise
// be reachable) and are NOT authorized by an RW/RO override, plus any
// user-declared extra deny paths that are likewise reachable. A path that is
// under no mount is already absent from the sandbox (ENOENT) and needs no
// cover. Ordering is stable; duplicates are collapsed.
func coverCandidates(sensitive []string, mounts []sandbox.Mount, ov *sandbox.PermissionOverrides) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, p := range sensitive {
		if overrideAuthorizes(p, ov) {
			continue
		}
		if underAnyMount(p, mounts) {
			add(p)
		}
	}
	if ov != nil {
		for _, p := range ov.Deny {
			if underAnyMount(p, mounts) {
				add(p)
			}
		}
	}
	return out
}

// underAnyMount reports whether p equals or is contained by any mount host
// path (separator-boundary match, so /home/u/project does not match a mount
// at /home/u/proj).
func underAnyMount(p string, mounts []sandbox.Mount) bool {
	for _, m := range mounts {
		if pathAtOrUnder(p, m.Host) {
			return true
		}
	}
	return false
}

// overrideAuthorizes reports whether p is covered by an RW or RO override
// (the user opted the path out of the sensitive shadow for this tool).
func overrideAuthorizes(p string, ov *sandbox.PermissionOverrides) bool {
	if ov == nil {
		return false
	}
	for _, base := range ov.RW {
		if pathAtOrUnder(p, base) {
			return true
		}
	}
	for _, base := range ov.RO {
		if pathAtOrUnder(p, base) {
			return true
		}
	}
	return false
}

// pathAtOrUnder is a separator-boundary containment check on cleaned paths:
// target equals base, or target starts with base + "/". Linux paths are
// case-sensitive, so no folding is applied.
func pathAtOrUnder(target, base string) bool {
	if target == "" || base == "" {
		return false
	}
	t := filepath.Clean(target)
	b := filepath.Clean(base)
	return t == b || strings.HasPrefix(t, b+"/")
}
