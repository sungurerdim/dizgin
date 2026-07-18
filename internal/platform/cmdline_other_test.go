// SPDX-License-Identifier: MIT

//go:build !windows

package platform

import "testing"

// On Unix exec uses argv arrays directly, so EscapeArg must be a strict
// pass-through: any quoting added here would end up inside the argument.
func TestEscapeArgUnixPassthrough(t *testing.T) {
	for _, in := range []string{"", "simple", "with space", `with"quote`, "tab\there"} {
		if got := EscapeArg(in); got != in {
			t.Errorf("EscapeArg(%q) = %q, want unchanged", in, got)
		}
	}
}

func TestBuildCommandLineUnix(t *testing.T) {
	if got := BuildCommandLine("tool", nil); got != "tool" {
		t.Errorf("no args: got %q, want %q", got, "tool")
	}
	got := BuildCommandLine("tool", []string{"--flag", "value with space"})
	want := "tool --flag value with space"
	if got != want {
		t.Errorf("BuildCommandLine = %q, want %q", got, want)
	}
}
