// SPDX-License-Identifier: MIT

//go:build darwin

package depclosure

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// requireCC skips the test if no C compiler is available to build the
// fixture binaries — CI images without Xcode Command Line Tools, for
// instance. This package's own logic (BFS/dedup/cycle-safety) is already
// covered platform-neutrally in depclosure_test.go via a fake graph; these
// tests specifically validate the real Mach-O parsing + @rpath resolution
// against binaries produced by the real toolchain, so a missing compiler
// means "cannot validate this layer here", not "broken".
func requireCC(t *testing.T) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no C compiler available, skipping Mach-O fixture test")
	}
	return cc
}

// buildFixture compiles a two-level dependency chain in dir:
//
//	main (executable) --@rpath--> libfoo.dylib --@rpath--> libbar.dylib
//
// and returns the absolute path to the compiled "main" executable. Both
// dylibs carry an install name of @rpath/<name>, and main/libfoo both
// carry an LC_RPATH of @loader_path/. — the same shape a Homebrew package
// uses (a binary in bin/, an @rpath-relative dylib in a sibling opt/*/lib).
func buildFixture(t *testing.T, cc, dir string) string {
	t.Helper()

	barC := filepath.Join(dir, "bar.c")
	fooC := filepath.Join(dir, "foo.c")
	mainC := filepath.Join(dir, "main.c")
	if err := os.WriteFile(barC, []byte("int bar_value(void) { return 42; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fooC, []byte("int bar_value(void);\nint foo_value(void) { return bar_value() + 1; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainC, []byte("int foo_value(void);\nint main(void) { return foo_value(); }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	libbar := filepath.Join(dir, "libbar.dylib")
	libfoo := filepath.Join(dir, "libfoo.dylib")
	mainBin := filepath.Join(dir, "main")

	run := func(args ...string) {
		cmd := exec.Command(cc, args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("cc %v: %v\n%s", args, err, out)
		}
	}

	run("-dynamiclib", "-o", libbar, barC,
		"-install_name", "@rpath/libbar.dylib")
	run("-dynamiclib", "-o", libfoo, fooC,
		"-L"+dir, "-lbar",
		"-install_name", "@rpath/libfoo.dylib",
		"-Wl,-rpath,@loader_path/.")
	run("-o", mainBin, mainC,
		"-L"+dir, "-lfoo",
		"-Wl,-rpath,@loader_path/.")

	return mainBin
}

func TestParseMachODeps_RpathChain(t *testing.T) {
	cc := requireCC(t)
	dir := t.TempDir()
	mainBin := buildFixture(t, cc, dir)

	deps, err := parseMachODeps(mainBin)
	if err != nil {
		t.Fatalf("parseMachODeps: %v", err)
	}
	libfoo := filepath.Join(dir, "libfoo.dylib")
	if !containsPath(deps, libfoo) {
		t.Errorf("main's direct deps %v should include %s", deps, libfoo)
	}
	// libbar is libfoo's dependency, not main's own — parseMachODeps is
	// single-level by design (Resolve does the recursion).
	libbar := filepath.Join(dir, "libbar.dylib")
	if containsPath(deps, libbar) {
		t.Errorf("main's direct deps should NOT include the transitive dep %s: %v", libbar, deps)
	}
}

func TestResolve_RealBinaryTransitiveClosure(t *testing.T) {
	cc := requireCC(t)
	dir := t.TempDir()
	mainBin := buildFixture(t, cc, dir)

	got := Resolve([]string{mainBin})
	libfoo := filepath.Join(dir, "libfoo.dylib")
	libbar := filepath.Join(dir, "libbar.dylib")
	if !containsPath(got, libfoo) {
		t.Errorf("closure %v should include direct dep %s", got, libfoo)
	}
	if !containsPath(got, libbar) {
		t.Errorf("closure %v should include transitive dep %s (via libfoo)", got, libbar)
	}
	if containsPath(got, mainBin) {
		t.Errorf("closure should never include the seed itself: %v", got)
	}
}

func TestParseMachODeps_NonMachOFileSkipped(t *testing.T) {
	dir := t.TempDir()
	textFile := filepath.Join(dir, "not-a-binary.txt")
	if err := os.WriteFile(textFile, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := parseMachODeps(textFile); err == nil {
		t.Error("parseMachODeps on a non-Mach-O file should return an error, not silently succeed")
	}
}

func TestParseMachODeps_MissingFile(t *testing.T) {
	if _, err := parseMachODeps("/no/such/binary/at/all"); err == nil {
		t.Error("parseMachODeps on a missing path should return an error")
	}
}

func containsPath(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
