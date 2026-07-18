// SPDX-License-Identifier: MIT

//go:build !windows

package main

import (
	"errors"
	"fmt"
	"io"
)

// diagnoseHangImpl is a no-op on non-Windows builds. The Wait Chain
// Traversal API is Windows-only; macOS and Linux have different
// debugging primitives (lsof, sample on macOS; /proc/<pid>/stack on
// Linux) that would warrant their own subcommands.
func diagnoseHangImpl(pid uint32, w io.Writer) error {
	fmt.Fprintf(w, "diagnose-hang: not implemented on this platform (pid=%d).\n", pid)
	fmt.Fprintln(w, "  Linux:  cat /proc/<pid>/stack or run 'sample <pid>' equivalent")
	fmt.Fprintln(w, "  macOS:  'sample <pid> 5' (built-in) or 'lldb -p <pid>'")
	return errors.New("diagnose-hang: not implemented on this platform")
}
