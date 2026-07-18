// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/config"
	"github.com/sungurerdim/dizgin/internal/security"
)

// runAddPath handles `dizgin add-path [--tool <name>] [--ro] <path>...`.
//
// Replaces the 5-way interactive access prompt retired in iter4. The new
// flow is explicit: the user observes a "tool referenced paths" report
// (printed by access_telemetry.Report at exit), copies the path they
// want exposed, and runs `dizgin add-path <path>`. The path is appended to
// the per-tool profile at ~/.dizgin/profiles/<tool>.yaml via the same
// AppendProfileEntries writer the prompt used to call.
//
// Defaults:
//   - --tool       inferred from $DIZGIN_TOOL or the most recently used
//     profile when only one tool exists; an explicit value
//     always wins.
//   - --ro         mount the path read-only. Without it the entry is
//     recorded as read-write.
//   - one or more positional paths follow the flags; relative paths are
//     resolved against the current working directory.
//
// Risky paths (security deny-list) are refused with a single-line error
// — the deny-list invariant says they must never appear in a profile.
func runAddPath(args []string) error {
	tool, readOnly, suggest, paths, err := parseAddPathFlags(args)
	if err != nil {
		return err
	}
	if paths == nil {
		return nil // --help was printed
	}

	if len(paths) == 0 {
		addPathUsage()
		return fmt.Errorf("add-path: no path supplied")
	}
	if tool == "" {
		// --suggest can tolerate an empty tool (the recommended command
		// printed at the end is informational only — the user can edit
		// it before running). Regular add-path needs the tool to write
		// the YAML.
		if suggest {
			tool = "<tool>"
		} else {
			return fmt.Errorf("add-path: --tool not specified and DIZGIN_TOOL is unset")
		}
	}

	// --suggest is advisory only: it inspects each path, asks Claude
	// (when ANTHROPIC_API_KEY is set) or applies a heuristic, and
	// prints a recommendation. No profile YAML is mutated; the user
	// re-runs `dizgin add-path` if they agree.
	if suggest {
		return runAddPathSuggest(paths, tool)
	}

	mode := "rw"
	if readOnly {
		mode = "ro"
	}

	entries, err := buildPathEntries(paths, mode)
	if err != nil {
		return err
	}

	added, err := AppendProfileEntries(tool, entries)
	if err != nil {
		return fmt.Errorf("add-path: %w", err)
	}
	if added == 0 {
		fmt.Fprintf(os.Stderr, brand.Name+": no new entries (already present in %s)\n",
			filepath.Join(userProfilesDir(), strings.ToLower(tool)+".yaml"))
		return nil
	}
	profilePath := filepath.Join(userProfilesDir(), strings.ToLower(tool)+".yaml")
	fmt.Fprintf(os.Stderr, brand.Name+": %d path(s) added to %s — re-run dizgin %s to apply.\n",
		added, profilePath, tool)
	return nil
}

// parseAddPathFlags parses dizgin add-path flags. Returns (tool, readOnly, suggest, paths, err).
// When --help is encountered paths is nil and err is nil — caller should return nil.
func parseAddPathFlags(args []string) (tool string, readOnly bool, suggest bool, paths []string, err error) {
	tool = os.Getenv(brand.Env("TOOL"))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "--help":
			addPathUsage()
			return "", false, false, nil, nil
		case a == "--ro" || a == "--read-only":
			readOnly = true
		case a == "--suggest":
			suggest = true
		case a == "--tool":
			if i+1 >= len(args) {
				return "", false, false, nil, fmt.Errorf("add-path: --tool requires a tool name")
			}
			i++
			tool = args[i]
		case strings.HasPrefix(a, "--tool="):
			tool = a[len("--tool="):]
		case strings.HasPrefix(a, "-"):
			return "", false, false, nil, fmt.Errorf("add-path: unknown flag %q", a)
		default:
			paths = append(paths, a)
		}
	}
	return tool, readOnly, suggest, paths, nil
}

// buildPathEntries resolves each path to an absolute value, checks the deny-list,
// and assembles the ConfigDirEntry slice ready to pass to AppendProfileEntries.
func buildPathEntries(paths []string, mode string) ([]config.ConfigDirEntry, error) {
	entries := make([]config.ConfigDirEntry, 0, len(paths))
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, fmt.Errorf("add-path: resolve %q: %w", p, err)
		}
		if risky, reason := security.IsRiskyPath(abs); risky {
			return nil, fmt.Errorf("add-path: refusing risky path %s (%s)", abs, reason)
		}
		entries = append(entries, config.ConfigDirEntry{
			Path:   abs,
			Mode:   mode,
			Source: "manual",
		})
	}
	return entries, nil
}

func addPathUsage() {
	fmt.Fprintln(os.Stderr, "Usage: dizgin add-path [--tool <name>] [--ro|--suggest] <path>...")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Appends one or more paths to the per-tool profile so the next dizgin run mounts")
	fmt.Fprintln(os.Stderr, "them. Use after a 'tool referenced paths' hint at session exit.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Flags:")
	fmt.Fprintln(os.Stderr, "  --tool <name>    Target profile name. Defaults to $DIZGIN_TOOL.")
	fmt.Fprintln(os.Stderr, "  --ro             Mark the mount read-only (default: read-write).")
	fmt.Fprintln(os.Stderr, "  --suggest        Advisory mode — print a mode recommendation per path")
	fmt.Fprintln(os.Stderr, "                   using a heuristic (offline) and, when ANTHROPIC_API_KEY is")
	fmt.Fprintln(os.Stderr, "                   set, a single Claude Haiku round trip. No YAML is written.")
	fmt.Fprintln(os.Stderr, "  -h, --help       Show this help.")
}
