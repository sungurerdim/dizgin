// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"
	"slices"
	"sort"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/credential"
)

// buildToolEnv builds the final environment slice passed to box.Start.
// It starts with the current process environment, then overrides with
// discovered credentials, then applies explicit CLI overrides last.
//
// scratchDir, when non-empty, is used as the per-session value for
// TEMP/TMP/TMPDIR so Bun SEA / Node tools that extract embedded
// runtimes (e.g. `$bunfs`) write into the per-session scratch tree
// instead of the host's %TEMP%. The scratch dir is created by the
// restricted backend and cleaned up on session exit.
// Opt-out: DIZGIN_NO_TEMP_OVERRIDE=1.
func buildToolEnv(creds []credential.Credential, cliOverrides []string, scratchDir string) []string {
	overrides := buildOverrideMap(creds, cliOverrides, scratchDir)
	result := applyEnvOverrides(os.Environ(), overrides)
	return applyTerminalDefaults(result)
}

// buildOverrideMap merges credential key-value pairs, CLI overrides, and the
// optional per-session scratch directory into a single override map. Priority
// (highest first): CLI overrides → credentials → scratchDir temp vars.
func buildOverrideMap(creds []credential.Credential, cliOverrides []string, scratchDir string) map[string]string {
	overrides := make(map[string]string, len(creds)+len(cliOverrides)+3)
	for _, c := range creds {
		overrides[c.Key] = c.Value
	}
	for _, kv := range cliOverrides {
		k, v := credential.SplitKV(kv)
		overrides[k] = v
	}
	// Per-session TEMP/TMP/TMPDIR override. The scratch dir is created by
	// the restricted backend during backend.Create; pointing the tool at it
	// lets Bun SEA and similar self-extracting runtimes write their $bunfs
	// cache to a writable path. Applied BEFORE CLI overrides so an explicit
	// `-e TMP=foo` still wins — that's the documented escape hatch.
	if scratchDir != "" && os.Getenv(brand.Env("NO_TEMP_OVERRIDE")) != "1" {
		for _, k := range []string{"TEMP", "TMP", "TMPDIR"} {
			if _, hasCLI := overrides[k]; !hasCLI {
				overrides[k] = scratchDir
			}
		}
	}
	return overrides
}

// applyEnvOverrides applies overrides onto base, replacing matching keys
// in-place and appending new keys (sorted for determinism).
func applyEnvOverrides(base []string, overrides map[string]string) []string {
	result := make([]string, 0, len(base)+len(overrides))
	replaced := make(map[string]bool, len(overrides))
	for _, kv := range base {
		k, _ := credential.SplitKV(kv)
		if v, ok := overrides[k]; ok {
			result = append(result, k+"="+v)
			replaced[k] = true
		} else {
			result = append(result, kv)
		}
	}
	// Add new keys that weren't in the original env (sorted for determinism).
	newKeys := make([]string, 0, len(overrides))
	for k := range overrides {
		if !replaced[k] {
			newKeys = append(newKeys, k)
		}
	}
	sort.Strings(newKeys)
	for _, k := range newKeys {
		result = append(result, k+"="+overrides[k])
	}
	return result
}

// applyTerminalDefaults injects TERM/COLORTERM/FORCE_COLOR/COLUMNS/LINES into
// env when they are not already present. This ensures Node.js TUI tools get
// sensible color and size defaults inside the sandbox.
//
// Windows hosts typically lack TERM; FORCE_COLOR=3 enables truecolor as a
// fallback for chalk/supports-color when isatty() returns inconsistently.
// COLUMNS/LINES let tools that skip ioctl(TIOCGWINSZ) know the terminal size.
func applyTerminalDefaults(env []string) []string {
	hasTermVar := make(map[string]bool, 5)
	for _, kv := range env {
		k, _ := credential.SplitKV(kv)
		switch k {
		case "TERM", "COLORTERM", "FORCE_COLOR", "COLUMNS", "LINES":
			hasTermVar[k] = true
		}
	}
	termDefaults := []struct{ k, v string }{
		{"TERM", "xterm-256color"},
		{"COLORTERM", "truecolor"},
		{"FORCE_COLOR", "3"},
	}
	if cols, rows, ok := currentTerminalSize(); ok {
		termDefaults = append(termDefaults,
			struct{ k, v string }{"COLUMNS", fmt.Sprintf("%d", cols)},
			struct{ k, v string }{"LINES", fmt.Sprintf("%d", rows)},
		)
	}
	for _, def := range termDefaults {
		if !hasTermVar[def.k] {
			env = append(env, def.k+"="+def.v)
		}
	}
	return env
}

// buildPassthroughEnv returns a []string{"KEY=VAL",...} slice by reading
// the named env vars (or all if "*") from the host process environment.
// These are applied as overrides with higher priority than profile env defaults.
func buildPassthroughEnv(passthrough []string) []string {
	if len(passthrough) == 0 {
		return nil
	}
	if slices.Contains(passthrough, "*") {
		return os.Environ()
	}
	result := make([]string, 0, len(passthrough))
	for _, key := range passthrough {
		if val := os.Getenv(key); val != "" {
			result = append(result, key+"="+val)
		}
	}
	return result
}
