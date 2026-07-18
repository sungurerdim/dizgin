// SPDX-License-Identifier: MIT

//go:build darwin

package seatbelt

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sungurerdim/dizgin/internal/config"
	"github.com/sungurerdim/dizgin/internal/sandbox"
)

// ── sbplQuotePath ─────────────────────────────────────────────────────────────

func TestSbplQuotePath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/simple/path", `"/simple/path"`},
		{`/path/with"quote`, `"/path/with\"quote"`},
		{`/path\with\backslash`, `"/path\\with\\backslash"`},
		{"", `""`},
	}
	for _, c := range cases {
		got := sbplQuotePath(c.in)
		if got != c.want {
			t.Errorf("sbplQuotePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ── generateProfile ───────────────────────────────────────────────────────────

func TestGenerateProfile_Open(t *testing.T) {
	profile := generateProfile(sandbox.CreateOpts{Network: config.NetworkOpen}, nil)
	if !strings.Contains(profile, "(deny default)") {
		t.Error("profile missing deny default")
	}
	if !strings.Contains(profile, "(allow network*)") {
		t.Error("open policy: missing (allow network*)")
	}
}

func TestGenerateProfile_Blocked(t *testing.T) {
	profile := generateProfile(sandbox.CreateOpts{Network: config.NetworkBlocked}, nil)
	if strings.Contains(profile, "(allow network*)\n") {
		t.Error("blocked policy: profile should not allow network*")
	}
}

func TestGenerateProfile_AllowlistEmitsResolvedIPs(t *testing.T) {
	// Allowlist rules are keyed on pre-resolved IP literals, not hostnames
	// (SBPL filters per-IP). Pass IPs in directly — no DNS in the unit test.
	opts := sandbox.CreateOpts{
		Network:   config.NetworkAllowlist,
		Allowlist: []string{"api.anthropic.com"},
	}
	profile := generateProfile(opts, []string{"203.0.113.7", "2606:4700::1"})

	if strings.Contains(profile, "api.anthropic.com") {
		t.Error("allowlist must emit resolved IPs, not the hostname (SBPL ignores hostname rules)")
	}
	for _, want := range []string{`"203.0.113.7:443"`, `"203.0.113.7:80"`, `"2606:4700::1:443"`} {
		if !strings.Contains(profile, want) {
			t.Errorf("allowlist: missing rule for %s", want)
		}
	}
	if !strings.Contains(profile, `(remote udp "*:53")`) {
		t.Error("allowlist: DNS must stay open")
	}
}

func TestResolveAllowlistIPs_FailClosed(t *testing.T) {
	ctx := context.Background()
	if _, err := resolveAllowlistIPs(ctx, nil); err == nil {
		t.Error("empty allowlist must be an error (fail-closed)")
	}
	if _, err := resolveAllowlistIPs(ctx, []string{"10.0.0.0/8"}); err == nil {
		t.Error("CIDR entry must be rejected (SBPL is per-IP)")
	}
	if _, err := resolveAllowlistIPs(ctx, []string{"this-host-does-not-exist.invalid"}); err == nil {
		t.Error("unresolvable host must fail closed")
	}
}

func TestGenerateProfile_MountPaths(t *testing.T) {
	opts := sandbox.CreateOpts{
		Mounts: []sandbox.Mount{
			{Host: "/home/user/project", ReadOnly: false},
			{Host: "/usr/local/bin", ReadOnly: true},
		},
	}
	profile := generateProfile(opts, nil)
	if !strings.Contains(profile, `"/home/user/project"`) {
		t.Error("mount path not found in profile")
	}
	if !strings.Contains(profile, "(allow file-write*") {
		t.Error("rw mount: expected file-write rule")
	}
	if strings.Contains(profile, `(allow file-write* (subpath "/usr/local/bin"))`) {
		t.Error("read-only mount should not have file-write rule")
	}
}

// ── R1 sensitive-surface deny ──────────────────────────────────────────────────

func TestGenerateProfile_DeniesSensitivePaths(t *testing.T) {
	home, _ := filepath.EvalSymlinks(t.TempDir())
	t.Setenv("HOME", home)
	ssh := filepath.Join(home, ".ssh")

	profile := generateProfile(sandbox.CreateOpts{Network: config.NetworkBlocked}, nil)

	wantDeny := "(deny file-read* file-write* (subpath " + sbplQuotePath(ssh) + "))"
	if !strings.Contains(profile, wantDeny) {
		t.Errorf("profile missing sensitive deny for %s\n--- profile ---\n%s", ssh, profile)
	}

	// A single-file SSOT entry (config.json) must use (literal ...), not subpath.
	dockerCfg := filepath.Join(home, ".docker", "config.json")
	wantFile := "(deny file-read* file-write* (literal " + sbplQuotePath(dockerCfg) + "))"
	if !strings.Contains(profile, wantFile) {
		t.Errorf("profile missing literal deny for file %s", dockerCfg)
	}
}

func TestGenerateProfile_DenyPrecedesOverrideAllow(t *testing.T) {
	home, _ := filepath.EvalSymlinks(t.TempDir())
	t.Setenv("HOME", home)
	ssh := filepath.Join(home, ".ssh")

	opts := sandbox.CreateOpts{
		Network:             config.NetworkBlocked,
		PermissionOverrides: &sandbox.PermissionOverrides{RW: []string{ssh}},
	}
	profile := generateProfile(opts, nil)

	denyIdx := strings.Index(profile, "(deny file-read* file-write* (subpath "+sbplQuotePath(ssh))
	allowIdx := strings.LastIndex(profile, "(allow file-write* (subpath "+sbplQuotePath(ssh)+"))")
	if denyIdx < 0 || allowIdx < 0 {
		t.Fatalf("expected both deny and re-allow for RW override %s", ssh)
	}
	if allowIdx < denyIdx {
		t.Error("override allow must come AFTER the sensitive deny (SBPL last-match-wins)")
	}
}

func TestGenerateProfile_ROOverrideKeepsWriteDenied(t *testing.T) {
	home, _ := filepath.EvalSymlinks(t.TempDir())
	t.Setenv("HOME", home)
	ssh := filepath.Join(home, ".ssh")

	opts := sandbox.CreateOpts{
		Network:             config.NetworkBlocked,
		PermissionOverrides: &sandbox.PermissionOverrides{RO: []string{ssh}},
	}
	profile := generateProfile(opts, nil)

	if !strings.Contains(profile, "(allow file-read* (subpath "+sbplQuotePath(ssh)+"))") {
		t.Error("RO override must re-allow read")
	}
	if strings.Contains(profile, "(allow file-write* (subpath "+sbplQuotePath(ssh)+"))") {
		t.Error("RO override must NOT re-allow write (write stays denied)")
	}
}

func TestSbplPathIsFile(t *testing.T) {
	cases := map[string]bool{
		"/h/.ssh":                  false, // leading-dot dir
		"/h/.netrc":                false, // leading-dot, no real ext
		"/h/.docker/config.json":   true,
		"/h/.config/gh/hosts.yml":  true,
		"/h/Library/Keychains":     false,
		"/h/creds.tfrc.json":       true,
		"/h/.local/share/keyrings": false,
	}
	for in, want := range cases {
		if got := sbplPathIsFile(in); got != want {
			t.Errorf("sbplPathIsFile(%q) = %v, want %v", in, got, want)
		}
	}
}

// ── backend.Create ───────────────────────────────────────────────────────────

func TestBackendCreate_OpenNetwork_Succeeds(t *testing.T) {
	b := &backend{}
	created, err := b.Create(context.Background(), &config.Config{}, sandbox.CreateOpts{Network: config.NetworkOpen})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	sb, ok := created.(*box)
	if !ok {
		t.Fatalf("Create returned %T, want *box", created)
	}
	if !strings.Contains(sb.profile, "(allow network*)") {
		t.Error("open policy: profile missing (allow network*)")
	}
}

func TestBackendCreate_Blocked_Succeeds(t *testing.T) {
	b := &backend{}
	created, err := b.Create(context.Background(), &config.Config{}, sandbox.CreateOpts{Network: config.NetworkBlocked})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created == nil {
		t.Fatal("Create returned nil box on success")
	}
}

func TestBackendCreate_AllowlistEmpty_FailsClosed(t *testing.T) {
	b := &backend{}
	_, err := b.Create(context.Background(), &config.Config{}, sandbox.CreateOpts{Network: config.NetworkAllowlist})
	if err == nil {
		t.Fatal("empty allowlist must fail closed, got nil error")
	}
}

func TestBackendCreate_AllowlistCIDR_FailsClosed(t *testing.T) {
	b := &backend{}
	_, err := b.Create(context.Background(), &config.Config{}, sandbox.CreateOpts{
		Network:   config.NetworkAllowlist,
		Allowlist: []string{"10.0.0.0/8"},
	})
	if err == nil {
		t.Fatal("CIDR allowlist entry must fail closed, got nil error")
	}
}

func TestBackend_LoadPermissionOverrides_NoProfileYet(t *testing.T) {
	b := &backend{}
	ov, err := b.LoadPermissionOverrides("no-such-tool-" + t.Name())
	if err != nil {
		t.Fatalf("LoadPermissionOverrides: unexpected error %v", err)
	}
	if ov != nil {
		t.Errorf("got %+v, want nil for a tool with no saved profile", ov)
	}
}

// ── writeProfileFile ─────────────────────────────────────────────────────────

func TestWriteProfileFile_ContentRoundTrips(t *testing.T) {
	const content = "(version 1)\n(deny default)\n"
	path, err := writeProfileFile(content)
	if err != nil {
		t.Fatalf("writeProfileFile: %v", err)
	}
	defer os.Remove(path) //nolint:errcheck

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	if string(got) != content {
		t.Errorf("file content = %q, want %q", got, content)
	}
	if !strings.HasSuffix(path, ".sb") {
		t.Errorf("path %q must use the .sb suffix", path)
	}
}
