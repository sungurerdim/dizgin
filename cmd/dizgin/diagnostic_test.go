// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"strings"
	"testing"
)

func TestDecorateError_NilReturnsEmpty(t *testing.T) {
	if got := decorateError(nil); got != "" {
		t.Errorf("decorateError(nil) = %q, want empty", got)
	}
}

func TestDecorateError_KnownPatterns(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantHint string
	}{
		{
			name:     "daemon unreachable hint",
			input:    "appcontainer: 3 system mount(s) need privileged stamping but no delegator is registered (start dizgind daemon)",
			wantHint: "dizgind start",
		},
		{
			name:     "sensitive DENY fail-closed hint",
			input:    "restricted: stamp deny on C:\\Users\\foo\\.ssh failed",
			wantHint: "fail-closed",
		},
		{
			name:     "unknown-tool / empty profiles hint",
			input:    "config: no profiles registered for tool",
			wantHint: "auto-detects",
		},
		{
			name:     "missing executable hint",
			input:    "exec: \"claude\": executable file not found in %PATH%",
			wantHint: "npm i -g @anthropic-ai/claude-code",
		},
		{
			name:     "ANTHROPIC_API_KEY hint",
			input:    "credential: ANTHROPIC_API_KEY not set",
			wantHint: "ANTHROPIC_API_KEY",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := decorateError(errors.New(c.input))
			if !strings.Contains(got, c.wantHint) {
				t.Errorf("decorateError(%q) = %q; expected hint substring %q",
					c.input, got, c.wantHint)
			}
			if !strings.Contains(got, "hint:") {
				t.Errorf("decorateError(%q) missing 'hint:' marker line: %s", c.input, got)
			}
		})
	}
}

func TestDecorateError_UnknownPatternPassThrough(t *testing.T) {
	in := errors.New("totally novel error nobody has classified yet")
	got := decorateError(in)
	if got != in.Error() {
		t.Errorf("expected pass-through for unknown error, got %q", got)
	}
}
