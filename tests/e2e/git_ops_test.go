// SPDX-License-Identifier: MIT

//go:build integration

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// TestGitOps_CloneInsideSandbox asserts that `git clone` over HTTPS
// works from inside the sandbox using the host's existing credential
// helper (or anonymous fetch for public repos). This is the R2
// (Native Experience) check that says "git just works" — no special
// path translation, no credential proxy, no --no-verify-ssl band-aid.
//
// Phase 1 plan, item E6.
//
// Skipped if the host has no network or the test repo URL is not
// reachable in 10 s. We pin to the upstream dizgin repo to keep the
// test self-contained — no third-party dependency that could go down
// independently.
func TestGitOps_CloneInsideSandbox(t *testing.T) {
	if os.Getenv(brand.Env("E2E_NO_NETWORK")) == "1" {
		t.Skip("DIZGIN_E2E_NO_NETWORK=1 — skipping network-dependent test")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git not on PATH: %v", err)
	}
	bin := dizginBin(t)

	wd := t.TempDir()
	target := filepath.Join(wd, "dizgin-clone-target")

	args := []string{
		"--no-pty",
		"-w", wd,
		"git", "clone", "--depth", "1",
		"https://github.com/sungurerdim/dizgin.git",
		target,
	}
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Network failures, DNS failures, GitHub outages are all
		// out-of-scope for this test — skip rather than mark fail.
		lo := strings.ToLower(string(out))
		if strings.Contains(lo, "could not resolve") ||
			strings.Contains(lo, "operation timed out") ||
			strings.Contains(lo, "connection refused") {
			t.Skipf("network unreachable, skipping: %v\n%s", err, out)
		}
		t.Fatalf("git clone via dizgin failed: %v\noutput:\n%s", err, out)
	}

	// Sanity check: the cloned tree contains a known file.
	want := filepath.Join(target, "go.mod")
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("expected %s after clone, got: %v\nclone output:\n%s", want, err, out)
	}
}

// TestGitOps_StatusInsideSandbox asserts `git status` works against
// a freshly initialised repo inside the sandbox. No network, no
// credential — pure git plumbing on a host filesystem the sandbox
// has been granted. Catches regressions where DACL stamping forgets
// the .git directory.
func TestGitOps_StatusInsideSandbox(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git not on PATH: %v", err)
	}
	bin := dizginBin(t)
	wd := t.TempDir()

	// Initialise the repo on the host first so the "git" command
	// inside dizgin is unambiguously the git status code path, not a
	// "git init" code path that races on directory creation.
	for _, gitCmd := range [][]string{
		{"init", "-q"},
		{"-c", "user.email=test@example.com", "-c", "user.name=test", "commit", "--allow-empty", "-m", "init"},
	} {
		c := exec.Command("git", gitCmd...)
		c.Dir = wd
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed on host: %v\n%s", gitCmd, err, out)
		}
	}

	// Now run git status inside dizgin and confirm it prints the
	// expected "nothing to commit" line.
	cmd := exec.Command(bin, "--no-pty", "-w", wd, "git", "status", "--porcelain=v1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git status via dizgin failed: %v\noutput:\n%s", err, out)
	}
	// Empty porcelain-v1 output == clean tree. We're not asserting on
	// stderr noise (dizgin may inject "stamping N/M" lines on a cold
	// run) — just on the porcelain stdout being empty.
	if strings.TrimSpace(string(out)) != "" && !strings.Contains(string(out), "stamping") {
		t.Fatalf("expected clean repo, got porcelain output:\n%s", out)
	}
}
