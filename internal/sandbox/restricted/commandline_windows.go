// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// Command-line + environment marshalling helpers for CreateProcessAsUserW.
// Extracted from box_windows.go (behaviour-preserving move) to keep the
// Box implementation file under the 500-line quality threshold.

// buildCommandLine quotes argv into the single-string command line
// CreateProcessW expects. Mirrors os/exec's escapeArg on Windows.
func buildCommandLine(cmd string, args []string) (string, error) {
	var sb strings.Builder
	cmdAbs, err := absExe(cmd)
	if err != nil {
		return "", err
	}
	sb.WriteString(escapeArg(cmdAbs))
	for _, a := range args {
		sb.WriteByte(' ')
		sb.WriteString(escapeArg(a))
	}
	return sb.String(), nil
}

// absExe resolves cmd to an absolute path so CreateProcessW does not
// silently fall through to its own search heuristic. Empty strings and
// already-absolute paths are returned unchanged.
func absExe(cmd string) (string, error) {
	if cmd == "" {
		return "", fmt.Errorf("empty command")
	}
	if filepath.IsAbs(cmd) {
		return cmd, nil
	}
	if abs, err := filepath.Abs(cmd); err == nil {
		if _, statErr := os.Stat(abs); statErr == nil {
			return abs, nil
		}
	}
	return cmd, nil
}

// escapeArg quotes a single argv entry per CommandLineToArgvW rules.
func escapeArg(arg string) string {
	if arg == "" {
		return `""`
	}
	needsQuote := false
	for i := 0; i < len(arg); i++ {
		c := arg[i]
		if c == ' ' || c == '\t' || c == '"' {
			needsQuote = true
			break
		}
	}
	if !needsQuote {
		return arg
	}
	var sb strings.Builder
	sb.WriteByte('"')
	bsCount := 0
	for i := 0; i < len(arg); i++ {
		c := arg[i]
		switch c {
		case '\\':
			bsCount++
		case '"':
			for j := 0; j < bsCount*2+1; j++ {
				sb.WriteByte('\\')
			}
			sb.WriteByte('"')
			bsCount = 0
		default:
			for j := 0; j < bsCount; j++ {
				sb.WriteByte('\\')
			}
			bsCount = 0
			sb.WriteByte(c)
		}
	}
	for j := 0; j < bsCount*2; j++ {
		sb.WriteByte('\\')
	}
	sb.WriteByte('"')
	return sb.String()
}

// utf16Env converts a key=value slice into the UTF-16 double-NUL
// terminated buffer CreateProcessW expects.
func utf16Env(env []string) ([]uint16, error) {
	var buf []uint16
	for _, kv := range env {
		w, err := windows.UTF16FromString(kv)
		if err != nil {
			return nil, fmt.Errorf("env[%q] UTF16: %w", kv, err)
		}
		buf = append(buf, w...)
	}
	buf = append(buf, 0) // double NUL terminator
	return buf, nil
}
