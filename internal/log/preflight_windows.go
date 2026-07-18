// SPDX-License-Identifier: MIT

//go:build windows

package log

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/security"
)

// preflightOnce gates PreflightWindows so multiple call sites (dizgin's
// run(), dizgind's runDaemon()) can all invoke it without printing
// the inventory more than once per process. The dump is information-
// dense; repeating it would just push the actual failure off the
// screen.
var preflightOnce sync.Once

// PreflightWindows emits a one-screen system inventory before any
// other work. Production behaviour: short-circuits on !IsVerbose so
// the function call itself adds zero output. Verbose mode dumps:
//
//   - dizgin / dizgind binary presence + size + mtime
//   - dizgind named-pipe reachability
//   - sensitive SSOT credential surfaces present on disk (the targets
//     restricted.Box.Start will stamp DENY ACEs on)
//   - ~/.dizgin state directories (audit JSONL count, permissions YAML
//     count, profiles YAML count)
//
// The pre-iter4 HCS / Hyper-V / runhcs / Microsoft-Windows-Hyper-V-
// Compute-Operational inventory was retired with the HCS container
// backend in iter4 — the restricted backend never reads any of it.
// Going through os.Stat / os.ReadFile / SSOT enumeration keeps the
// framework debuggable without shelling out to PowerShell or DISM.
func PreflightWindows() {
	if !IsVerbose() {
		return
	}
	preflightOnce.Do(runPreflight)
}

func runPreflight() {
	fmt.Fprintln(os.Stderr, "==== DIZGIN preflight inventory ====")
	defer fmt.Fprintln(os.Stderr, "==== /preflight inventory ====")

	preflightBinaries()
	preflightDaemon()
	preflightSensitivePaths()
	preflightDizginDirs()
}

func preflightBinaries() {
	fmt.Fprintln(os.Stderr, "[preflight] binaries:")
	progData := os.Getenv("ProgramData")
	if progData == "" {
		progData = `C:\ProgramData`
	}
	binDir := filepath.Join(progData, brand.Name, "bin")
	for _, name := range []string{brand.Name + ".exe", brand.DaemonName + ".exe"} {
		p := filepath.Join(binDir, name)
		info, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s: MISSING (%v)\n", name, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "  %s: %d bytes, mtime=%s\n",
			p, info.Size(), info.ModTime().Format("2006-01-02T15:04:05Z07:00"))
	}
	if exe, err := os.Executable(); err == nil {
		fmt.Fprintf(os.Stderr, "  running exe: %s\n", exe)
	}
}

// preflightDaemon checks the dizgind named pipe at the canonical path.
// The SSOT for this name is internal/daemon/transport_windows.go's
// pipeName constant — if that changes, update here in lockstep.
func preflightDaemon() {
	fmt.Fprintln(os.Stderr, "[preflight] daemon:")
	const pipePath = `\\.\pipe\dizgind`
	if _, err := os.Stat(pipePath); err != nil {
		fmt.Fprintf(os.Stderr, "  named pipe %s not present (daemon down)\n", pipePath)
	} else {
		fmt.Fprintf(os.Stderr, "  named pipe %s present\n", pipePath)
	}
}

// preflightSensitivePaths reports which entries from the SSOT exist on
// this host. Lines show "+ <path>" when present (the path will get a
// DENY ACE on next dizgin session) or "- <path>" when absent (the SSOT
// entry is logged but no stamp is applied). The list is short and
// stable; no recursion or stat-cost on credential trees themselves.
func preflightSensitivePaths() {
	fmt.Fprintln(os.Stderr, "[preflight] sensitive SSOT (credential surfaces):")
	home := os.Getenv("USERPROFILE")
	if home == "" {
		fmt.Fprintln(os.Stderr, "  USERPROFILE empty — SSOT cannot be expanded")
		return
	}
	paths := security.SensitiveDenyPaths(home)
	present, absent := 0, 0
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			fmt.Fprintf(os.Stderr, "  + %s\n", p)
			present++
		} else {
			fmt.Fprintf(os.Stderr, "  - %s\n", p)
			absent++
		}
	}
	fmt.Fprintf(os.Stderr, "  total: %d present, %d absent (%d SSOT entries)\n",
		present, absent, len(paths))
}

// preflightDizginDirs inventories the per-user state directories dizgin
// + dizgind write to. File counts come from a single ReadDir call per
// directory — no recursive walk, no content inspection.
func preflightDizginDirs() {
	fmt.Fprintln(os.Stderr, "[preflight] ~/.dizgin state:")
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		fmt.Fprintf(os.Stderr, "  UserHomeDir unresolved: %v\n", err)
		return
	}
	root := filepath.Join(home, brand.DotDir)
	if _, err := os.Stat(root); err != nil {
		fmt.Fprintf(os.Stderr, "  %s not present (no prior dizgin / dizgind runs)\n", root)
		return
	}
	for _, sub := range brand.StateSubdirs {
		dir := filepath.Join(root, sub)
		entries, err := os.ReadDir(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s/: absent\n", sub)
			continue
		}
		fmt.Fprintf(os.Stderr, "  %s/: %d entr%s\n", sub, len(entries), pluralY(len(entries)))
	}
}

// pluralY returns "y" for 1, "ies" otherwise. Used so "1 entry" and
// "5 entries" both render correctly in the preflight summary.
func pluralY(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
