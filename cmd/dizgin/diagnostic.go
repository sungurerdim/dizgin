// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"strings"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// errorHint maps a substring of an error message to a one-line
// remediation string. The matcher is greedy: the first hint whose
// pattern appears in the error wins. Patterns are case-insensitive.
//
// Order matters — list more specific patterns before general ones so
// "AppContainer SID not on DACL" wins over a bare "permission denied".
var errorHints = []struct {
	pattern string
	hint    string
}{
	// iter4 3-tier R model — category-aware hints, listed first so the
	// classifier's wrapped error wins over generic patterns.
	{
		pattern: "r1-a workdir stamp failed",
		hint:    "the project workdir DACL stamp failed — try `dizgin doctor`; verify the workdir is not on a read-only volume or remote share",
	},
	{
		pattern: "r1-b declared rw stamp failed",
		hint:    "a profile path in filesystem.read_write needs admin or removal — edit ~/.dizgin/profiles/<tool>.yaml",
	},
	{
		pattern: "r1-c declared ro stamp failed",
		hint:    "a profile path in filesystem.read_only could not be stamped — see docs/CONFIG.md#read_only, or remove the entry if the runtime no longer needs it",
	},
	{
		// emitted by box.Create when the daemon delegator is missing
		pattern: "no delegator is registered",
		hint:    "start the dizgind daemon: `dizgind start` (or run `dizgin doctor` to diagnose)",
	},
	{
		// fail-closed sensitive DENY rollback (backend.go)
		pattern: "stamp deny",
		hint:    "a sensitive-path DENY ACE could not be applied, so the session refused to start (fail-closed). Check that %USERPROFILE% is on a local NTFS volume; run `dizgind heal` to scan for leftover ACEs",
	},
	{
		// profile registry empty / unknown tool
		pattern: "no profiles registered",
		hint:    "drop a profile in ~/.dizgin/profiles/<tool>.yaml, or just run the tool — dizgin auto-detects an installed binary and writes a starter profile for you",
	},
	{
		// mount source path missing on host
		pattern: "mount source",
		hint:    "a path referenced by the tool profile does not exist on the host — edit ~/.dizgin/profiles/<tool>.yaml or remove the stale entry",
	},
	{
		// per-session scratch dir creation failed
		pattern: "scratch",
		hint:    "dizgin could not create its per-session scratch dir under %ProgramData%\\dizgin — check disk space and that the directory is writable (`dizgin doctor`)",
	},
	{
		// LookPath / exec.ErrNotFound style
		pattern: "executable file not found",
		hint:    "install the tool first (e.g. `npm i -g @anthropic-ai/claude-code`) or check that it's on $PATH",
	},
	{
		// our own findOnPath error
		pattern: "not found in search dirs",
		hint:    "ensure the tool's runtime DLLs are on $PATH; `dizgin doctor` shows what dizgin sees",
	},
	{
		// dizgind IPC unreachable
		pattern: "could not open " + brand.PipeName,
		hint:    "the dizgind daemon is not responding — try `dizgind start` or reboot the daemon process",
	},
	{
		// missing required env
		pattern: "anthropic_api_key",
		hint:    "set ANTHROPIC_API_KEY in your environment, or store it via `dizgin config set credential.anthropic`",
	},
	{
		// schema rejection from F5
		pattern: "field ",
		hint:    "your YAML has an unknown key (typo?). Profile/config schema enforces strict mode; see docs/CONFIG.md",
	},
}

// decorateError appends a remediation hint to err's message when the
// underlying message matches a known pattern. Returns the original
// error string if no pattern matches — callers can always fmt-print
// the result safely. Hints are formatted on a separate line so the
// raw error stays diff-able for log scrapers.
func decorateError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	lower := strings.ToLower(msg)
	for _, h := range errorHints {
		if strings.Contains(lower, h.pattern) {
			return fmt.Sprintf("%s\n  hint: %s", msg, h.hint)
		}
	}
	return msg
}
