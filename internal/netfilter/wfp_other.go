// SPDX-License-Identifier: MIT

//go:build !windows

package netfilter

// Apply is a no-op on non-Windows platforms: WFP is Windows-only. The
// Linux backend enforces network allowlists via nftables (CAP_NET_ADMIN)
// and macOS via the Seatbelt profile, both handled inside their own
// sandbox backends rather than through the daemon broker.
func Apply(sessionID, appPath string, allowlist []string) (string, error) {
	return "", ErrUnsupported
}

// Revoke is a no-op on non-Windows platforms.
func Revoke(sessionID string) error {
	return ErrUnsupported
}
