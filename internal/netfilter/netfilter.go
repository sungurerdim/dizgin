// SPDX-License-Identifier: MIT

// Package netfilter implements the user-mode WFP (Windows Filtering
// Platform) network allowlist enforcement that the elevated dizgind
// daemon applies on behalf of a dizgin session.
//
// Why the daemon and not dizgin: adding WFP filters at the ALE_AUTH_CONNECT
// layers requires FWPM_ACTRL_ADD on the layer, which the default WFP
// security descriptor grants only to Administrators + SYSTEM. dizgin runs
// non-elevated (zero-UAC cold start), so it cannot add filters itself.
// dizgind already elevates at `dizgind start`, so dizgin brokers the
// apply/revoke through the daemon IPC (TypeWFPApply / TypeWFPRevoke).
//
// Honest boundary: these are user-mode filters. A process running under
// the same user SID could enumerate and delete them. This is therefore
// *accidental-egress* protection (a tool reaching the wrong CDN, a curl
// in a test hitting the public internet) — NOT a defense against a
// hostile tool that actively tears down its own enforcement. The hard
// boundary remains R1 (filesystem DENY ACEs). Real network enforcement
// is a kernel-mode WFP callout driver, tracked as ROADMAP #1.
//
// The Apply/Revoke entry points are declared per-platform: a real WFP
// implementation on windows (wfp_windows.go) and a no-op stub elsewhere
// (wfp_other.go) so the daemon server stays platform-neutral.
package netfilter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// dnsLookupTimeout bounds the default resolver so a slow or hung DNS
// server cannot block Apply (and therefore session/daemon-handler
// startup) indefinitely.
const dnsLookupTimeout = 5 * time.Second

// ErrUnsupported is returned by Apply/Revoke on non-Windows platforms.
// The daemon translates it into an advisory IPC response so dizgin can
// degrade gracefully rather than failing the session.
var ErrUnsupported = errors.New("netfilter: WFP enforcement is Windows-only")

// ResolvedAllowlist is the outcome of turning a profile's
// network.allowlist (hostnames / literal IPs) into concrete addresses
// the WFP layer can match on, plus the entries that could not be
// represented so the caller can log them (no silent caps).
type ResolvedAllowlist struct {
	// IPv4 holds host-order uint32 addresses for FWP_UINT32 conditions.
	IPv4 []uint32
	// IPv6 holds 16-byte addresses for FWP_BYTE_ARRAY16 conditions.
	IPv6 [][16]byte
	// Skipped lists "entry: reason" strings for anything dropped
	// (unresolvable host, unsupported CIDR range, empty entry).
	Skipped []string
}

// Total returns the number of concrete permit addresses resolved.
func (r ResolvedAllowlist) Total() int { return len(r.IPv4) + len(r.IPv6) }

// ResolveAllowlist turns raw allowlist entries into concrete addresses.
//
// Supported entry forms:
//   - literal IPv4 / IPv6 ("203.0.113.5", "2001:db8::1")
//   - hostnames ("api.anthropic.com") — resolved via the host resolver
//     to every A / AAAA record
//
// CIDR ranges ("10.0.0.0/8") are NOT supported by the user-mode interim
// (an exact-match FWP_UINT32 condition cannot express a mask without the
// FWP_V4_ADDR_AND_MASK range type) and are reported in Skipped so the
// operator knows coverage is partial rather than silently dropped.
//
// Resolution is best-effort: an entry that fails to resolve is recorded
// in Skipped and the rest still produce permits. lookup is injectable so
// tests do not depend on live DNS.
func ResolveAllowlist(entries []string, lookup func(host string) ([]net.IP, error)) ResolvedAllowlist {
	if lookup == nil {
		lookup = func(host string) ([]net.IP, error) {
			ctx, cancel := context.WithTimeout(context.Background(), dnsLookupTimeout)
			defer cancel()
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
	}
	var out ResolvedAllowlist
	seen4 := make(map[uint32]struct{})
	seen6 := make(map[[16]byte]struct{})

	add := func(ip net.IP) {
		if v4 := ip.To4(); v4 != nil {
			h := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
			if _, dup := seen4[h]; !dup {
				seen4[h] = struct{}{}
				out.IPv4 = append(out.IPv4, h)
			}
			return
		}
		if v6 := ip.To16(); v6 != nil {
			var a [16]byte
			copy(a[:], v6)
			if _, dup := seen6[a]; !dup {
				seen6[a] = struct{}{}
				out.IPv6 = append(out.IPv6, a)
			}
		}
	}

	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			out.Skipped = append(out.Skipped, fmt.Sprintf("%s: CIDR ranges are unsupported in the user-mode WFP interim (exact IPs only)", entry))
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			add(ip)
			continue
		}
		ips, err := lookup(entry)
		if err != nil || len(ips) == 0 {
			out.Skipped = append(out.Skipped, fmt.Sprintf("%s: unresolvable host (%v)", entry, err))
			continue
		}
		for _, ip := range ips {
			add(ip)
		}
	}
	return out
}
