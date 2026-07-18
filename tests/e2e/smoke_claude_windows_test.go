// SPDX-License-Identifier: MIT

//go:build windows && integration

// Package e2e covers the live-tool smoke test that the HCS-era
// smoke_claude_windows scaffold (deleted in 94ea514) used to run.
// AppContainer's host_path == guest_path model means the host's
// claude.exe (or any other AI CLI on PATH) runs natively under the
// AC sandbox, so the canonical smoke check is "does claude --version
// still answer when invoked through dizgin?".
//
// The test skips when no live tool is installed; CI runners that
// install claude (or aider, codex, etc.) get coverage automatically.
// At least one of the configured tools must be on PATH for the
// smoke test to run; if none are, skip (no infrastructure → no
// signal).
package e2e

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const smokeTimeout = 30 * time.Second

// smokeTool is a tool we know answers --version cleanly and is small
// enough to be a CI-friendly install target. The list expands as we
// onboard more profiles into the smoke matrix.
type smokeTool struct {
	name        string // executable name as the user would type it
	versionFlag string // typically --version, sometimes -v
	wantSubstr  string // substring expected in stdout/stderr
}

var smokeTools = []smokeTool{
	{name: "claude", versionFlag: "--version", wantSubstr: "claude"},
	{name: "aider", versionFlag: "--version", wantSubstr: "aider"},
	{name: "codex", versionFlag: "--version", wantSubstr: "codex"},
}

// TestSmokeLiveTool_VersionRoundtrip walks the smokeTools list and
// runs `dizgin <tool> --version` for each one that is on PATH. Skips
// when no tool is installed (CI without smoke tooling, local dev
// box without any AI CLI).
func TestSmokeLiveTool_VersionRoundtrip(t *testing.T) {
	bin := dizginBin(t)

	any := false
	for _, st := range smokeTools {
		if _, err := exec.LookPath(st.name); err != nil {
			continue
		}
		any = true
		t.Run(st.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), smokeTimeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, "--no-pty", st.name, st.versionFlag)
			cmd.Dir = t.TempDir()
			out, err := cmd.CombinedOutput()
			if ctx.Err() == context.DeadlineExceeded {
				t.Fatalf("%s --version timed out: %s", st.name, out)
			}
			if err != nil {
				t.Fatalf("dizgin %s %s failed: %v\noutput: %s", st.name, st.versionFlag, err, out)
			}
			if !strings.Contains(strings.ToLower(string(out)), strings.ToLower(st.wantSubstr)) {
				t.Errorf("expected %q substring in output, got: %s", st.wantSubstr, out)
			}
		})
	}
	if !any {
		t.Skip("no smoke tool (claude / aider / codex) on PATH — skipping live smoke test")
	}
}
