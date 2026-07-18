// SPDX-License-Identifier: MIT

package main

import (
	"testing"
)

func TestRootCmd_HasSubcommands(t *testing.T) {
	cmds := rootCmd.Commands()
	names := make(map[string]bool)
	for _, c := range cmds {
		names[c.Name()] = true
	}
	for _, want := range []string{"start", "stop", "status", "completion"} {
		if !names[want] {
			t.Errorf("missing subcommand %q", want)
		}
	}
}

func TestStartCmd_ForegroundFlag(t *testing.T) {
	f := startCmd.Flags().Lookup("foreground")
	if f == nil {
		t.Fatal("--foreground flag not registered on start command")
	}
}

func TestStatusCmd_JSONFlag(t *testing.T) {
	f := statusCmd.Flags().Lookup("json")
	if f == nil {
		t.Fatal("--json flag not registered on status command")
	}
}

func TestFormatUptime(t *testing.T) {
	cases := []struct {
		secs int64
		want string
	}{
		{0, "-"},
		{-1, "-"},
		{45, "45s"},
		{90, "1m30s"},
		{3661, "1h01m"},
	}
	for _, c := range cases {
		got := formatUptime(c.secs)
		if got != c.want {
			t.Errorf("formatUptime(%d) = %q, want %q", c.secs, got, c.want)
		}
	}
}

func TestShortenPath(t *testing.T) {
	long := `C:\Users\someone\very\long\path\to\project`
	short := shortenPath(long, 20)
	if len([]rune(short)) > 21 { // allow 1 extra for the "…" rune
		t.Errorf("shortenPath result too long: %q (len=%d)", short, len(short))
	}
	// Short path must pass through unchanged.
	short2 := shortenPath("short", 20)
	if short2 != "short" {
		t.Errorf("shortenPath(short) = %q, want %q", short2, "short")
	}
}
