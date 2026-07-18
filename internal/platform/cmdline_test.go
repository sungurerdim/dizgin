// SPDX-License-Identifier: MIT

//go:build windows

package platform

import "testing"

func TestEscapeArg(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"simple", "simple"},
		{"", `""`},
		{"with space", `"with space"`},
		{`with"quote`, `"with\"quote"`},
		{`path\to\dir\`, `path\to\dir\`},
		{`C:\Program Files\tool`, `"C:\Program Files\tool"`},
		{`arg with "quotes" and spaces`, `"arg with \"quotes\" and spaces"`},
		{`back\\slash"`, `"back\\slash\""`},
		{"no-special", "no-special"},
		{"tab\there", "\"tab\there\""},
	}
	for _, tt := range tests {
		got := EscapeArg(tt.in)
		if got != tt.want {
			t.Errorf("EscapeArg(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestBuildCommandLine(t *testing.T) {
	got := BuildCommandLine("tool.exe", nil)
	if got != "tool.exe" {
		t.Errorf("no args: got %q", got)
	}

	got = BuildCommandLine("C:\\Program Files\\tool.exe", []string{"--flag", "value with space"})
	want := `"C:\Program Files\tool.exe" --flag "value with space"`
	if got != want {
		t.Errorf("BuildCommandLine = %q, want %q", got, want)
	}
}
