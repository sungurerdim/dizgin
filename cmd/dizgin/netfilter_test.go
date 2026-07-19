// SPDX-License-Identifier: MIT

package main

import (
	"runtime"
	"testing"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/config"
)

// TST-16: wfpEnabled branch logic.
//
// applyNetworkFilter and revokeNetworkFilter both call daemon.ApplyNetworkFilter
// / daemon.RevokeNetworkFilter which dial the real named pipe. Those paths
// require a live dizgind daemon and are therefore deferred to e2e tests.
// The decidable branch logic lives entirely in wfpEnabled, which is pure.

func cfgWithPolicy(policy config.NetworkPolicy, allowlist []string) *config.Config {
	return &config.Config{
		Network: config.NetworkConfig{
			Policy:    policy,
			Allowlist: allowlist,
		},
	}
}

// TestWFPEnabled_EnvGateDisables verifies that DIZGIN_NO_WFP=1 short-circuits
// regardless of the policy configuration.
func TestWFPEnabled_EnvGateDisables(t *testing.T) {
	t.Setenv(brand.Env("NO_WFP"), "1")

	cfg := cfgWithPolicy(config.NetworkAllowlist, []string{"api.anthropic.com"})
	if wfpEnabled(cfg) {
		t.Error("wfpEnabled: want false when DIZGIN_NO_WFP=1, got true")
	}
}

// TestWFPEnabled_EmptyAllowlistDisables verifies that a NetworkAllowlist policy
// with an empty allowlist does not enable WFP (nothing to enforce).
func TestWFPEnabled_EmptyAllowlistDisables(t *testing.T) {
	t.Setenv(brand.Env("NO_WFP"), "")

	cfg := cfgWithPolicy(config.NetworkAllowlist, []string{})
	if wfpEnabled(cfg) {
		t.Error("wfpEnabled: want false for empty allowlist, got true")
	}
}

// TestWFPEnabled_NilAllowlistDisables verifies that a nil allowlist is treated
// the same as empty.
func TestWFPEnabled_NilAllowlistDisables(t *testing.T) {
	t.Setenv(brand.Env("NO_WFP"), "")

	cfg := cfgWithPolicy(config.NetworkAllowlist, nil)
	if wfpEnabled(cfg) {
		t.Error("wfpEnabled: want false for nil allowlist, got true")
	}
}

// TestWFPEnabled_OpenPolicyDisables verifies that an "open" network policy does
// not enable WFP even when an allowlist is populated (allowlist is ignored for
// the open policy).
func TestWFPEnabled_OpenPolicyDisables(t *testing.T) {
	t.Setenv(brand.Env("NO_WFP"), "")

	cfg := cfgWithPolicy(config.NetworkOpen, []string{"api.anthropic.com"})
	if wfpEnabled(cfg) {
		t.Error("wfpEnabled: want false for NetworkOpen policy, got true")
	}
}

// TestWFPEnabled_BlockedPolicyDisables verifies that a "blocked" network policy
// does not enable WFP (WFP enforcement is only for allowlist mode).
func TestWFPEnabled_BlockedPolicyDisables(t *testing.T) {
	t.Setenv(brand.Env("NO_WFP"), "")

	cfg := cfgWithPolicy(config.NetworkBlocked, []string{"api.anthropic.com"})
	if wfpEnabled(cfg) {
		t.Error("wfpEnabled: want false for NetworkBlocked policy, got true")
	}
}

// TestWFPEnabled_AllowlistWithEntries verifies the enabled path: allowlist
// policy + non-empty allowlist + env gate not set. WFP is a Windows-only API
// (internal/netfilter/wfp_other.go no-ops everywhere else — macOS/Linux
// allowlist enforcement lives inside their own sandbox backend instead), so
// wfpEnabled must stay false on every other GOOS even when every other
// condition is met. Without this OS gate, macOS/Linux sessions dialed the
// elevated-daemon broker anyway and printed a Windows-only remediation hint
// ("start the dizgind daemon for WFP enforcement") that can never apply
// there — verified reproducing on macOS 26.5.2.
func TestWFPEnabled_AllowlistWithEntries(t *testing.T) {
	t.Setenv(brand.Env("NO_WFP"), "")

	cfg := cfgWithPolicy(config.NetworkAllowlist, []string{"api.anthropic.com", "api.github.com"})
	want := runtime.GOOS == "windows"
	if got := wfpEnabled(cfg); got != want {
		t.Errorf("wfpEnabled: want %v for allowlist policy with entries and no env gate on GOOS=%s, got %v", want, runtime.GOOS, got)
	}
}

// TestWFPEnabled_EnvGateValueZeroDoesNotDisable verifies that DIZGIN_NO_WFP=0
// does not disable WFP (only the literal "1" disables) — on Windows, where
// WFP can apply at all; every other GOOS stays false regardless (see
// TestWFPEnabled_AllowlistWithEntries).
func TestWFPEnabled_EnvGateValueZeroDoesNotDisable(t *testing.T) {
	t.Setenv(brand.Env("NO_WFP"), "0")

	cfg := cfgWithPolicy(config.NetworkAllowlist, []string{"api.anthropic.com"})
	want := runtime.GOOS == "windows"
	if got := wfpEnabled(cfg); got != want {
		t.Errorf("wfpEnabled: DIZGIN_NO_WFP=0 should only enable WFP on Windows (GOOS=%s), want %v got %v", runtime.GOOS, want, got)
	}
}
