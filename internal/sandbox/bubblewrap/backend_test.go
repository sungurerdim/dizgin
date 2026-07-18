// SPDX-License-Identifier: MIT

//go:build linux

package bubblewrap

import (
	"context"
	"strings"
	"testing"

	"github.com/sungurerdim/dizgin/internal/config"
	"github.com/sungurerdim/dizgin/internal/sandbox"
)

// ── insertBeforeSep ───────────────────────────────────────────────────────────

func TestInsertBeforeSep_Found(t *testing.T) {
	args := []string{"--bind", "/a", "/a", "--", "cmd"}
	got := insertBeforeSep(args, []string{"--seccomp", "3"})
	want := []string{"--bind", "/a", "/a", "--seccomp", "3", "--", "cmd"}
	if len(got) != len(want) {
		t.Fatalf("len: got %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestInsertBeforeSep_NotFound(t *testing.T) {
	args := []string{"--bind", "/a", "/a"}
	got := insertBeforeSep(args, []string{"--extra"})
	// Extra appended at end.
	if got[len(got)-1] != "--extra" {
		t.Errorf("extra not appended: %v", got)
	}
}

// ── buildBwrapArgs network policy ─────────────────────────────────────────────

func TestBuildBwrapArgs_NetworkBlocked(t *testing.T) {
	b := &box{opts: sandbox.CreateOpts{Network: config.NetworkBlocked}}
	args, err := b.buildBwrapArgs("/bin/sh", nil)
	if err != nil {
		t.Fatalf("buildBwrapArgs: %v", err)
	}
	if !contains(args, "--unshare-net") {
		t.Error("blocked: expected --unshare-net")
	}
}

func TestBuildBwrapArgs_NetworkOpen(t *testing.T) {
	b := &box{opts: sandbox.CreateOpts{Network: config.NetworkOpen}}
	args, err := b.buildBwrapArgs("/bin/sh", nil)
	if err != nil {
		t.Fatalf("buildBwrapArgs: %v", err)
	}
	if !contains(args, "--share-net") {
		t.Error("open: expected --share-net")
	}
	if contains(args, "--unshare-net") {
		t.Error("open: unexpected --unshare-net")
	}
}

func TestCreate_AllowlistFailsClosed(t *testing.T) {
	// Linux filtered allowlist is not enforced yet; Create must refuse
	// rather than silently downgrade to a blocked (or open) network.
	b := &backend{}
	_, err := b.Create(context.Background(), &config.Config{},
		sandbox.CreateOpts{Network: config.NetworkAllowlist, Allowlist: []string{"github.com"}})
	if err == nil {
		t.Fatal("allowlist policy must fail closed on Linux until filtering is implemented")
	}
	if !strings.Contains(err.Error(), "not yet enforced") {
		t.Errorf("error should explain the limitation, got: %v", err)
	}
}

func TestBuildBwrapArgs_SecurityFlags(t *testing.T) {
	b := &box{opts: sandbox.CreateOpts{}}
	args, err := b.buildBwrapArgs("/bin/sh", nil)
	if err != nil {
		t.Fatalf("buildBwrapArgs: %v", err)
	}
	if !contains(args, "--die-with-parent") {
		t.Error("expected --die-with-parent")
	}
	if !contains(args, "--new-session") {
		t.Error("expected --new-session")
	}
}

func TestBuildBwrapArgs_WorkdirChdir(t *testing.T) {
	b := &box{opts: sandbox.CreateOpts{Workdir: "/tmp/myproject"}}
	args, err := b.buildBwrapArgs("/bin/sh", nil)
	if err != nil {
		t.Fatalf("buildBwrapArgs: %v", err)
	}
	idx := indexOf(args, "--chdir")
	if idx < 0 || idx+1 >= len(args) || args[idx+1] != "/tmp/myproject" {
		t.Errorf("--chdir not set correctly in args: %v", args)
	}
}

// helpers

func contains(args []string, s string) bool {
	for _, a := range args {
		if a == s {
			return true
		}
	}
	return false
}

func indexOf(args []string, s string) int {
	for i, a := range args {
		if a == s {
			return i
		}
	}
	return -1
}
