// SPDX-License-Identifier: MIT

package bubblewrap

import (
	"path/filepath"
	"testing"

	"github.com/sungurerdim/dizgin/internal/sandbox"
)

// coverCandidates is platform-neutral, so these run on any OS (the bwrap
// arg emission that consumes the result is linux-tagged and tested there).

func TestCoverCandidates_OnlyUnderMount(t *testing.T) {
	home := "/home/dev"
	sensitive := []string{
		filepath.Join(home, ".ssh"),                // under the mount → covered
		filepath.Join(home, ".aws", "credentials"), // NOT under mount → ENOENT, skip
	}
	mounts := []sandbox.Mount{{Host: home + "/.ssh", Guest: home + "/.ssh"}}

	got := coverCandidates(sensitive, mounts, nil)
	if len(got) != 1 || got[0] != filepath.Join(home, ".ssh") {
		t.Fatalf("coverCandidates = %v, want just the mounted .ssh", got)
	}
}

func TestCoverCandidates_WholeHomeMounted(t *testing.T) {
	home := "/home/dev"
	sensitive := []string{
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".gnupg"),
	}
	mounts := []sandbox.Mount{{Host: home, Guest: home}} // whole home mounted

	got := coverCandidates(sensitive, mounts, nil)
	if len(got) != 2 {
		t.Fatalf("coverCandidates = %v, want both sensitive dirs covered", got)
	}
}

func TestCoverCandidates_OverrideAuthorizesSkip(t *testing.T) {
	home := "/home/dev"
	ssh := filepath.Join(home, ".ssh")
	sensitive := []string{ssh}
	mounts := []sandbox.Mount{{Host: home, Guest: home}}

	ovRW := &sandbox.PermissionOverrides{RW: []string{ssh}}
	if got := coverCandidates(sensitive, mounts, ovRW); len(got) != 0 {
		t.Errorf("RW override must skip the cover, got %v", got)
	}
	ovRO := &sandbox.PermissionOverrides{RO: []string{ssh}}
	if got := coverCandidates(sensitive, mounts, ovRO); len(got) != 0 {
		t.Errorf("RO override must skip the cover, got %v", got)
	}
}

func TestCoverCandidates_UserDenyExtra(t *testing.T) {
	home := "/home/dev"
	extra := filepath.Join(home, "secret.env")
	mounts := []sandbox.Mount{{Host: home, Guest: home}}
	ov := &sandbox.PermissionOverrides{Deny: []string{extra}}

	got := coverCandidates(nil, mounts, ov)
	if len(got) != 1 || got[0] != extra {
		t.Errorf("user Deny extra under a mount must be covered, got %v", got)
	}

	// The same extra deny NOT under any mount is ENOENT already → no cover.
	if got := coverCandidates(nil, nil, ov); len(got) != 0 {
		t.Errorf("Deny extra not under a mount must be skipped, got %v", got)
	}
}

func TestPathAtOrUnder_SeparatorBoundary(t *testing.T) {
	if !pathAtOrUnder("/home/dev/.ssh", "/home/dev") {
		t.Error(".ssh should be under /home/dev")
	}
	if !pathAtOrUnder("/home/dev", "/home/dev") {
		t.Error("equal paths should match")
	}
	if pathAtOrUnder("/home/dev-2/x", "/home/dev") {
		t.Error("/home/dev-2 must NOT match /home/dev (boundary bug)")
	}
	if pathAtOrUnder("", "/x") || pathAtOrUnder("/x", "") {
		t.Error("empty inputs must not match")
	}
}
