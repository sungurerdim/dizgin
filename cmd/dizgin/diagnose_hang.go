// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

// diagnoseHangCmd wires dizgin's external Wait Chain Traversal probe.
// Usage: dizgin diagnose-hang <pid>
//
// Use case: another shell is running `dizgin --no-pty -- claude --help`
// and it hung. Run this command from a second shell with claude.exe's
// PID (taken from Task Manager or `tasklist /fi "imagename eq claude.exe"`).
// The output lists every thread + its wait-chain primitives, so the
// "what handle is the busy thread blocked on?" question gets a name.
//
// Non-Windows builds get a stub that prints a friendly message — the
// underlying WCT API is Windows-only and not worth shimming.
var diagnoseHangCmd = &cobra.Command{
	Use:          "diagnose-hang <pid>",
	Short:        "Walk the Wait Chain of a hung process (Windows only)",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runDiagnoseHang,
}

func init() {
	rootCmd.AddCommand(diagnoseHangCmd)
}

func runDiagnoseHang(_ *cobra.Command, args []string) error {
	pid, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid pid %q: %w", args[0], err)
	}
	return diagnoseHangImpl(uint32(pid), os.Stdout)
}
