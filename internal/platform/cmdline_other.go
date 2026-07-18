// SPDX-License-Identifier: MIT

//go:build !windows

package platform

import "strings"

// EscapeArg is a no-op on non-Windows platforms. Windows command line
// escaping is not needed on Unix where exec uses argv directly.
func EscapeArg(s string) string {
	return s
}

// BuildCommandLine joins a command and arguments with spaces.
// On Unix this is only used for display purposes — actual execution
// uses argv arrays, not command line strings.
func BuildCommandLine(cmd string, args []string) string {
	if len(args) == 0 {
		return cmd
	}
	return cmd + " " + strings.Join(args, " ")
}
