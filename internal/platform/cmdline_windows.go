// SPDX-License-Identifier: MIT

package platform

import "strings"

// EscapeArg escapes a single argument for a Windows command line.
// It follows the Microsoft C/C++ runtime escaping convention used by
// CommandLineToArgvW: arguments containing spaces, tabs, or double-quotes
// are wrapped in double-quotes, with internal quotes and backslashes
// escaped as needed. This is equivalent to syscall.EscapeArg.
func EscapeArg(s string) string {
	if len(s) == 0 {
		return `""`
	}
	needsQuote := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '"':
			needsQuote = true
		}
	}
	if !needsQuote {
		return s
	}

	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		default:
			slashes = 0
			b.WriteByte(s[i])
		case '\\':
			slashes++
			b.WriteByte('\\')
		case '"':
			for j := 0; j < slashes; j++ {
				b.WriteByte('\\')
			}
			slashes = 0
			b.WriteByte('\\')
			b.WriteByte('"')
		}
	}
	for j := 0; j < slashes; j++ {
		b.WriteByte('\\')
	}
	b.WriteByte('"')
	return b.String()
}

// BuildCommandLine joins a command and its arguments into a properly
// escaped Windows command line string. Each argument is individually
// escaped using EscapeArg.
func BuildCommandLine(cmd string, args []string) string {
	if len(args) == 0 {
		return EscapeArg(cmd)
	}
	parts := make([]string, 0, 1+len(args))
	parts = append(parts, EscapeArg(cmd))
	for _, a := range args {
		parts = append(parts, EscapeArg(a))
	}
	return strings.Join(parts, " ")
}
