// SPDX-License-Identifier: MIT

package netfilter

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

func fakeLookup(m map[string][]net.IP) func(string) ([]net.IP, error) {
	return func(host string) ([]net.IP, error) {
		if ips, ok := m[host]; ok {
			return ips, nil
		}
		return nil, fmt.Errorf("no such host")
	}
}

func TestResolveAllowlist_literalsAndHosts(t *testing.T) {
	lookup := fakeLookup(map[string][]net.IP{
		"api.example.com": {net.ParseIP("203.0.113.7"), net.ParseIP("2001:db8::1")},
	})
	r := ResolveAllowlist([]string{
		"203.0.113.5",     // literal v4
		"2001:db8::2",     // literal v6
		"api.example.com", // host → 1 v4 + 1 v6
		"203.0.113.5",     // dup v4 — must be deduped
	}, lookup)

	if len(r.IPv4) != 2 {
		t.Errorf("IPv4 = %v, want 2 unique", r.IPv4)
	}
	if len(r.IPv6) != 2 {
		t.Errorf("IPv6 = %v, want 2 unique", r.IPv6)
	}
	if r.Total() != 4 {
		t.Errorf("Total = %d, want 4", r.Total())
	}
	// 203.0.113.5 host-order = 0xCB007105
	want := uint32(203)<<24 | uint32(0)<<16 | uint32(113)<<8 | uint32(5)
	found := false
	for _, ip := range r.IPv4 {
		if ip == want {
			found = true
		}
	}
	if !found {
		t.Errorf("expected host-order %#x in %v", want, r.IPv4)
	}
}

func TestResolveAllowlist_skipsCIDRAndUnresolvable(t *testing.T) {
	r := ResolveAllowlist([]string{
		"10.0.0.0/8",       // CIDR — unsupported
		"nonexistent.host", // unresolvable
		"",                 // empty — silently dropped, not in Skipped
	}, fakeLookup(nil))

	if r.Total() != 0 {
		t.Errorf("Total = %d, want 0", r.Total())
	}
	if len(r.Skipped) != 2 {
		t.Fatalf("Skipped = %v, want 2 (CIDR + unresolvable)", r.Skipped)
	}
	joined := strings.Join(r.Skipped, "|")
	if !strings.Contains(joined, "CIDR") {
		t.Errorf("expected CIDR skip reason in %v", r.Skipped)
	}
	if !strings.Contains(joined, "unresolvable") {
		t.Errorf("expected unresolvable skip reason in %v", r.Skipped)
	}
}
