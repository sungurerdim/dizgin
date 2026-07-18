// SPDX-License-Identifier: MIT

package main

import (
	"reflect"
	"testing"
)

// parseToolArgs simulates the full dizgin argument-parsing pipeline used in run():
//  1. parseOwnFlags  — dizgin's own flags (workdir, config, no-pty, …)
//  2. parseArgs      — env overrides vs tool command
//  3. strip leading "--" from toolExtraArgs
//
// Returns (toolBin, toolExtraArgs, envOverrides).
func parseToolArgs(args []string) (toolBin string, toolExtra []string, envOverrides []string) {
	remaining := parseOwnFlags(args)
	if remaining == nil {
		return "", nil, nil
	}
	toolArgs, envOvr := parseArgs(remaining)
	if len(toolArgs) == 0 {
		return "", nil, envOvr
	}
	bin := toolArgs[0]
	extra := toolArgs[1:]
	if len(extra) > 0 && extra[0] == "--" {
		extra = extra[1:]
	}
	return bin, extra, envOvr
}

func TestDoubleDashSeparatorAfterTool(t *testing.T) {
	// "dizgin claude -- --version": "--" between tool and tool-flags must be stripped.
	resetGlobals(t)
	bin, extra, _ := parseToolArgs([]string{"claude", "--", "--version"})
	if bin != "claude" {
		t.Fatalf("toolBin: got %q, want %q", bin, "claude")
	}
	if !reflect.DeepEqual(extra, []string{"--version"}) {
		t.Errorf("toolExtra: got %v, want [--version]", extra)
	}
}

func TestDoubleDashSeparatorWithCopFlags(t *testing.T) {
	// "dizgin -w /proj claude -- --flag": workdir parsed, "--" stripped from tool args.
	resetGlobals(t)
	bin, extra, _ := parseToolArgs([]string{"-w", "/proj", "claude", "--", "--flag"})
	if bin != "claude" {
		t.Fatalf("toolBin: got %q, want %q", bin, "claude")
	}
	if !reflect.DeepEqual(extra, []string{"--flag"}) {
		t.Errorf("toolExtra: got %v, want [--flag]", extra)
	}
	if workdir != "/proj" {
		t.Errorf("workdir: got %q, want /proj", workdir)
	}
}

func TestNoDoubleDash(t *testing.T) {
	// "dizgin claude --version": no "--", args passed through unchanged.
	resetGlobals(t)
	bin, extra, _ := parseToolArgs([]string{"claude", "--version"})
	if bin != "claude" {
		t.Fatalf("toolBin: got %q, want %q", bin, "claude")
	}
	if !reflect.DeepEqual(extra, []string{"--version"}) {
		t.Errorf("toolExtra: got %v, want [--version]", extra)
	}
}

func TestDoubleDashBeforeTool(t *testing.T) {
	// "dizgin -- claude --version": "--" before tool name, consumed by parseOwnFlags.
	resetGlobals(t)
	bin, extra, _ := parseToolArgs([]string{"--", "claude", "--version"})
	if bin != "claude" {
		t.Fatalf("toolBin: got %q, want %q", bin, "claude")
	}
	if !reflect.DeepEqual(extra, []string{"--version"}) {
		t.Errorf("toolExtra: got %v, want [--version]", extra)
	}
}

func TestDoubleDashOnly(t *testing.T) {
	// "dizgin --": no tool specified.
	resetGlobals(t)
	bin, extra, _ := parseToolArgs([]string{"--"})
	if bin != "" || len(extra) != 0 {
		t.Errorf("expected empty tool, got bin=%q extra=%v", bin, extra)
	}
}
