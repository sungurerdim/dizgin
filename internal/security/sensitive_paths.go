// SPDX-License-Identifier: MIT

package security

import (
	"path/filepath"
	"strings"
)

// This file is the platform-neutral core of the sensitive-path SSOT. The
// per-OS files (sensitive_paths_{windows,darwin,linux}.go) supply three
// things and nothing else:
//
//	var sensitiveRelativePaths []string  // home-relative, native separators
//	const sensitiveFoldCase bool         // case-insensitive match? (NTFS/APFS yes, ext4 no)
//	func sensitiveHome() string          // %USERPROFILE% or $HOME
//
// The matcher and the exported API below are shared, so adding a
// credential surface on one OS never silently diverges the match/expand
// logic from the others.
//
// Convention (all OSes): an entry ending in a file extension targets
// exactly that file; everything else is a directory whose whole subtree
// is sensitive. The credential surfaces captured are the ones a generic
// AI coding tool has no business reading — SSH/PGP keys, cloud-CLI token
// caches (AWS/Azure/GCP), Kubernetes/Docker/GitHub/Terraform credentials,
// the OS credential vault, and browser cookie stores (session-token theft
// via cookie DB reads is a documented exfiltration path).

// SensitiveDenyPaths returns absolute paths derived from home for every
// SSOT entry. Non-existent paths are returned anyway: enforcement layers
// skip missing paths, and a path the user creates later is covered on the
// next session. Returns nil for an empty home so callers fall into a
// no-op branch instead of stamping junk rooted at the filesystem root.
func SensitiveDenyPaths(home string) []string {
	if home == "" {
		return nil
	}
	out := make([]string, 0, len(sensitiveRelativePaths))
	for _, rel := range sensitiveRelativePaths {
		out = append(out, filepath.Join(home, rel))
	}
	return out
}

// SensitiveRelativePaths returns a copy of the raw SSOT list (native
// separators). Useful for docs generators and heal inventories that
// render the list without binding to a concrete home root.
func SensitiveRelativePaths() []string {
	out := make([]string, len(sensitiveRelativePaths))
	copy(out, sensitiveRelativePaths)
	return out
}

// IsSensitiveDeny reports whether host matches, or lives under, one of the
// SSOT sensitive paths for the current user's home. Convenience wrapper
// over IsSensitiveDenyAt for callers that don't parameterize the home root.
func IsSensitiveDeny(host string) bool {
	return IsSensitiveDenyAt(host, sensitiveHome())
}

// IsSensitiveDenyAt is the testable form: it accepts an explicit home root
// so tests can pin it without touching environment state. The match is a
// separator-boundary prefix match (so ~/.sshd_config does NOT match ~/.ssh)
// with per-OS case folding — mandatory on NTFS and APFS, where a ".SSH"
// spelling would otherwise bypass a ".ssh" rule.
func IsSensitiveDenyAt(host, home string) bool {
	if host == "" || home == "" {
		return false
	}
	hostClean := foldPath(filepath.Clean(host))
	sep := string(filepath.Separator)
	for _, rel := range sensitiveRelativePaths {
		abs := foldPath(filepath.Clean(filepath.Join(home, rel)))
		if hostClean == abs || strings.HasPrefix(hostClean, abs+sep) {
			return true
		}
	}
	return false
}

// foldPath lower-cases the path on case-insensitive filesystems so the
// prefix match cannot be defeated by case variation. On case-sensitive
// filesystems (Linux ext4/btrfs) it is a pass-through.
func foldPath(p string) string {
	if sensitiveFoldCase {
		return strings.ToLower(p)
	}
	return p
}
