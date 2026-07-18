// SPDX-License-Identifier: MIT

//go:build windows

package security

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsVolumeRoot(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{`C:\`, true},
		{`D:\`, true},
		{`c:\`, true},
		{`C:\Windows`, false},
		{`C:\Users\foo`, false},
		// UNC share roots are also volume roots — non-admin DACL writes
		// fail the same way, so the guard rejects them too.
		{`\\server\share`, true},
		{``, false},
	}
	for _, c := range cases {
		if got := IsVolumeRoot(c.in); got != c.want {
			t.Errorf("IsVolumeRoot(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestIsSystemPath(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{`C:\Windows`, true},
		{`C:\Windows\System32`, true},
		{`C:\Program Files`, true},
		{`C:\Program Files (x86)\Foo`, true},
		{`C:\ProgramData\dizgin`, true},
		{`C:\Users\Sungur\Project`, false},
		{`D:\GitHub\dizgin`, false},
		{`C:\Windows-but-not`, false},
		{``, false},
	}
	for _, c := range cases {
		if got := IsSystemPath(c.in); got != c.want {
			t.Errorf("IsSystemPath(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestIsIntegrityDenied_VolumeRoot(t *testing.T) {
	denied, reason := IsIntegrityDenied(`C:\`)
	if !denied {
		t.Fatalf("expected volume root denial")
	}
	if reason == "" {
		t.Fatalf("expected non-empty reason for volume root")
	}
}

func TestIsIntegrityDenied_SystemRoot(t *testing.T) {
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		t.Skip("SystemRoot env var missing")
	}
	denied, _ := IsIntegrityDenied(sysRoot)
	if !denied {
		t.Fatalf("expected SystemRoot to be denied")
	}
}

func TestIsIntegrityDenied_NeutralPath(t *testing.T) {
	tmp := t.TempDir()
	// TempDir is under %TEMP%, which path_classify excludes from the
	// denylist precisely so per-session scratch dirs remain stampable.
	denied, reason := IsIntegrityDenied(tmp)
	if denied {
		t.Fatalf("expected %s under TempDir to be stampable, got denied: %s", tmp, reason)
	}
}

func TestDirContainsExecutable(t *testing.T) {
	tmp := t.TempDir()
	if DirContainsExecutable(tmp) {
		t.Fatalf("empty tmpdir should not contain executables")
	}
	exe := filepath.Join(tmp, "marker.exe")
	if err := os.WriteFile(exe, []byte("MZ"), 0o600); err != nil {
		t.Fatalf("write probe exe: %v", err)
	}
	if !DirContainsExecutable(tmp) {
		t.Fatalf("expected tmpdir to register an executable after writing marker.exe")
	}
}

func TestDirContainsExecutable_ReadError(t *testing.T) {
	// Non-existent dir → fail-closed (returns true).
	if !DirContainsExecutable(`Z:\nonexistent\very\deep\path`) {
		t.Fatalf("expected fail-closed true for unreadable dir")
	}
}
