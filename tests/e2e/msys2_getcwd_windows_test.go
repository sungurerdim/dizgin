// SPDX-License-Identifier: MIT

//go:build windows && integration

// Package e2e: MSYS2 happy-path verifier. iter6 removed `dizgind setup`
// because the restricted token preserves `SeChangeNotifyPrivilege` and
// NTFS traversal works without an explicit ALL APPLICATION PACKAGES
// grant on volume roots. This test confirms the iter6 assumption end
// to end: a Git-for-Windows MSYS2 process inside a dizgin session can
// resolve getcwd() through the user-profile chain and read git
// metadata.
//
// Replaces the deferred R2-02 known issue: post-iter6, `dizgin git status`
// should exit 0 with no host-side setup.
package e2e

import (
	"os/exec"
	"strings"
	"testing"
)

// TestMSYS2GetcwdInsideCopSession expects a working git binary on PATH
// (MSYS2 flavour, the one shipped by Git-for-Windows). Skips if missing
// or if the dizgin binary isn't built. Unlike the pre-iter6 variant, this
// test no longer gates on a dizgind-setup marker — there is no marker.
func TestMSYS2GetcwdInsideCopSession(t *testing.T) {
	bin := dizginBin(t)

	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not on PATH — skipping MSYS2 getcwd test")
	}

	// Heuristic: Git-for-Windows ships under \Program Files\Git or
	// %LOCALAPPDATA%\Programs\Git. Stand-alone git.exe builds (e.g.
	// MinGit) work but won't exercise the MSYS2 getcwd path we care
	// about. Soft check via the resolved binary's parent.
	lower := strings.ToLower(gitPath)
	if !strings.Contains(lower, "git") {
		t.Skipf("git binary at %q does not look like MSYS2 git — skipping", gitPath)
	}

	// Make a tiny throwaway repo so 'git status' has something to
	// report. We use t.TempDir so the post-test cleanup is automatic
	// and so no real repo metadata leaks into the test.
	wd := t.TempDir()
	if err := initEmptyRepo(wd); err != nil {
		t.Fatalf("init repo: %v", err)
	}

	cmd := exec.Command(bin, "-w", wd, "--no-pty", "git", "status")
	cmd.Dir = wd
	out, runErr := cmd.CombinedOutput()
	if runErr != nil {
		t.Fatalf("dizgin git status failed: %v\noutput: %s", runErr, out)
	}
	lowerOut := strings.ToLower(string(out))
	if !strings.Contains(lowerOut, "branch") && !strings.Contains(lowerOut, "commit") {
		t.Fatalf("dizgin git status output missing expected markers (no 'branch'/'commit' keywords):\n%s", out)
	}
}

// initEmptyRepo runs `git init` outside dizgin so the test only measures
// the in-sandbox getcwd path on the subsequent `dizgin git status` call.
// Returns the error verbatim — caller handles t.Fatalf.
func initEmptyRepo(dir string) error {
	cmd := exec.Command("git", "init", "-q", dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return &execFail{stage: "git init", err: err, out: string(out)}
	}
	return nil
}

type execFail struct {
	stage string
	err   error
	out   string
}

func (e *execFail) Error() string {
	return e.stage + ": " + e.err.Error() + " — " + e.out
}
