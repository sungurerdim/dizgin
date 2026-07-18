// SPDX-License-Identifier: MIT

//go:build !windows

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// healCmd on non-Windows is a no-op stub. The DACL drift detector
// only makes sense for the Windows restricted-backend path; the
// macOS Seatbelt and Linux bubblewrap backends do not apply per-
// session ACEs and therefore have no drift surface to scan.
var healCmd = &cobra.Command{
	Use:   "heal",
	Short: "Scan the sensitive SSOT for ACL drift (Windows only — no-op on this platform)",
	RunE: func(_ *cobra.Command, _ []string) error {
		fmt.Fprintln(os.Stderr, "dizgind heal: no-op on this platform (DACL drift scan is Windows-only)")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(healCmd)
}
