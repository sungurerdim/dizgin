// SPDX-License-Identifier: MIT

//go:build integration

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestAccessTelemetry_ReportOnMissingPath drives dizgin against a tool whose
// stderr does NOT echo the offending path, then verifies the post-exit
// access telemetry report still surfaces it via the locale-agnostic
// args-fallback (accessTelemetry.NoteFromArgs).
//
// Why a "command-not-found" / silent-fail invocation instead of `cmd /c
// type <missing>`:
//
//	The regex library in cmd/dizgin/access_telemetry.go matches localized
//	"Cannot find the file specified" / "No such file or directory" /
//	"FileNotFoundException" / etc. On Türkçe Windows, `cmd /c type`
//	emits "Sistem belirtilen yolu bulamıyor." — without the path in
//	the body — so the regex layer cannot extract the sentinel. The
//	args-fallback is the second-layer mechanism that scans argv for
//	absolute non-existent paths when the tool exits non-zero, so it
//	works on every locale.
//
//	Picking a guaranteed-missing command name as argv[0] of /c keeps
//	the regex layer dark on every locale (the "is not recognized…"
//	error body never includes the sentinel path), so the args-fallback
//	is the ONLY mechanism that can surface the sentinel here. The test
//	thus deterministically validates that args-fallback is wired into
//	the report — independently of the host locale.
//
// The test stays on non-PTY mode so stderr is captured via CombinedOutput
// without needing a real terminal.
func TestAccessTelemetry_ReportOnMissingPath(t *testing.T) {
	bin := dizginBin(t)
	wd := t.TempDir()

	// Construct a sentinel path the tool can't reach. The args-fallback
	// scans every argv element and flags absolute paths that don't exist
	// on the host filesystem when the tool exits non-zero.
	sentinel := filepath.Join(wd, "nonexistent-subdir", "nonexistent-file.txt")

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// "dizgin_no_such_command_xyz" is not a real cmd.exe builtin or
		// PATH binary, so cmd.exe emits an "is not recognized as an
		// internal or external command…" error (localized but never
		// containing the sentinel path). Exit code is 1 (or 9009 on
		// some Windows builds) — non-zero, which is what NoteFromArgs
		// gates on. The sentinel is appended as a separate argv entry
		// so dizgin's args-scan sees it directly.
		cmd = exec.Command(bin, "-w", wd, "--no-pty",
			"cmd", "/c", "dizgin_no_such_command_xyz", sentinel)
	} else {
		// GNU coreutils 'false' silently exits 1 regardless of args.
		// /usr/bin/false is POSIX, present on every supported Unix.
		cmd = exec.Command(bin, "-w", wd, "--no-pty",
			"false", sentinel)
	}
	cmd.Dir = wd
	// DIZGIN_NO_ACCESS_TELEMETRY="" keeps the observer enabled (the env
	// var disables telemetry when set to "1" — empty value is the
	// default-on path).
	cmd.Env = append(os.Environ(), "DIZGIN_NO_ACCESS_TELEMETRY=")
	out, _ := cmd.CombinedOutput()
	s := string(out)

	// The args-fallback must have flagged the sentinel; Report() must
	// have emitted it under the "not mounted" header. These three
	// assertions together prove the args-fallback path is live:
	//
	//   1. sentinel filename appears in output  → entry made it past
	//      uniqueEntries() and the risky-path filter
	//   2. "not mounted" header appears         → Report() ran
	//   3. "[READ]" tag appears                 → mode is what
	//      NoteFromArgs always assigns (synthetic "open 'X'" lines
	//      hit the accessModeRead regex). If the regex layer had
	//      caught a locale-specific message we'd likely see [UNKNOWN]
	//      instead, so this assertion also guards against accidental
	//      regex-layer wins on English Windows.
	if !strings.Contains(s, "nonexistent-file.txt") {
		t.Errorf("access telemetry did not surface the missing path via args-fallback\noutput: %s", s)
	}
	if !strings.Contains(s, "not mounted") {
		t.Errorf("access telemetry report header missing\noutput: %s", s)
	}
	if !strings.Contains(s, "[READ]") {
		t.Errorf("expected args-fallback entry to be tagged [READ]\noutput: %s", s)
	}
}
