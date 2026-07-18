// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Build metadata — set by GoReleaser (or the Makefile `build` target) via
// `-X main.version=...` ldflags. The defaults below are the values a plain
// `go build` produces when no ldflags are supplied, so a dev build still
// has something to print instead of the empty string.
//
// Cobra reads rootCmd.Version to auto-generate the --version flag. We also
// expose a `version` subcommand (mirroring dizgin) that prints commit, build
// date, and Go toolchain info, because the one-liner from --version is not
// enough for bug reports.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// versionCmd prints detailed build metadata. `dizgind version` is analogous
// to `dizgin version` and exists for diagnostic parity between the two binaries
// — users filing an issue should be able to run one command per binary to
// gather everything the maintainer needs.
var versionCmd = &cobra.Command{
	Use:           "version",
	Short:         "Print detailed version information",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		fmt.Printf("dizgind %s\n", version)
		fmt.Printf("  commit: %s\n", commit)
		fmt.Printf("  built:  %s\n", date)
		fmt.Printf("  go:     %s\n", runtime.Version())
		return nil
	},
}
