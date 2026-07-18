// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"strings"
	"testing"
)

// TST-02: pure-function tests for add_path_suggest.go

// ── parseLLMSuggestion ────────────────────────────────────────────────────────

func TestParseLLMSuggestion_ValidModes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantMode string
	}{
		{
			name:     "rw mode",
			input:    `{"mode":"rw","reason":"project working directory"}`,
			wantMode: "rw",
		},
		{
			name:     "ro mode",
			input:    `{"mode":"ro","reason":"system tool directory"}`,
			wantMode: "ro",
		},
		{
			name:     "deny mode",
			input:    `{"mode":"deny","reason":"contains SSH private keys"}`,
			wantMode: "deny",
		},
		{
			name:     "skip mode",
			input:    `{"mode":"skip","reason":"path does not exist"}`,
			wantMode: "skip",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseLLMSuggestion(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.mode != tc.wantMode {
				t.Errorf("mode: want %q, got %q", tc.wantMode, got.mode)
			}
			if got.reason == "" {
				t.Error("reason should be non-empty for valid response")
			}
		})
	}
}

func TestParseLLMSuggestion_PrefixTextTolerated(t *testing.T) {
	// The parser must handle a model prefix before the JSON object.
	input := `Here is my answer: {"mode":"ro","reason":"system path"}`
	got, err := parseLLMSuggestion(input)
	if err != nil {
		t.Fatalf("unexpected error with prefix text: %v", err)
	}
	if got.mode != "ro" {
		t.Errorf("mode: want ro, got %q", got.mode)
	}
}

func TestParseLLMSuggestion_MalformedJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "truncated JSON",
			input: `{"mode":"rw","reason":`,
		},
		{
			name:  "invalid value type for mode",
			input: `{"mode":123,"reason":"foo"}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseLLMSuggestion(tc.input)
			if err == nil {
				t.Error("expected error for malformed JSON, got nil")
			}
		})
	}
}

func TestParseLLMSuggestion_EmptyInput(t *testing.T) {
	_, err := parseLLMSuggestion("")
	if err == nil {
		t.Error("expected error for empty input, got nil")
	}
}

func TestParseLLMSuggestion_NoJSONBraces(t *testing.T) {
	_, err := parseLLMSuggestion("just some text with no JSON at all")
	if err == nil {
		t.Error("expected error when no JSON object found, got nil")
	}
}

func TestParseLLMSuggestion_UnknownMode(t *testing.T) {
	_, err := parseLLMSuggestion(`{"mode":"readwrite","reason":"bad mode"}`)
	if err == nil {
		t.Error("expected error for unknown mode, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "unknown mode") {
		t.Errorf("error should mention 'unknown mode', got: %v", err)
	}
}

// ── buildLLMSuggestPrompt ─────────────────────────────────────────────────────

func TestBuildLLMSuggestPrompt_ContainsRequiredFields(t *testing.T) {
	c := pathContext{
		abs:      `/home/user/project`,
		kind:     "dir",
		category: "user-profile",
		exists:   true,
	}
	prompt := buildLLMSuggestPrompt(c, "claude")

	checks := []string{
		"claude",             // tool name
		`/home/user/project`, // path
		"dir",                // kind
		"user-profile",       // category
		"rw",                 // mode option
		"ro",                 // mode option
		"deny",               // mode option
		"skip",               // mode option
		`"mode"`,             // JSON key instruction
	}
	for _, want := range checks {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
}

func TestBuildLLMSuggestPrompt_SensitiveNote(t *testing.T) {
	c := pathContext{
		abs:         `/home/user/.ssh`,
		kind:        "dir",
		category:    "sensitive (SSOT credential surface)",
		exists:      true,
		isSensitive: true,
	}
	prompt := buildLLMSuggestPrompt(c, "claude")

	if !strings.Contains(prompt, "sensitive") {
		t.Error("prompt should mention 'sensitive' when isSensitive=true")
	}
	if !strings.Contains(prompt, "deny") {
		t.Error("prompt should mention 'deny' as safe default for sensitive paths")
	}
}

func TestBuildLLMSuggestPrompt_NonSensitiveHasNoSSOTNote(t *testing.T) {
	c := pathContext{
		abs:         `/home/user/projects`,
		kind:        "dir",
		category:    "user-profile",
		exists:      true,
		isSensitive: false,
	}
	prompt := buildLLMSuggestPrompt(c, "cursor")

	// The SSOT-specific note must not appear for non-sensitive paths.
	if strings.Contains(prompt, "SSOT credential surface") {
		t.Error("prompt should not mention SSOT note for non-sensitive path")
	}
}

// ── heuristicSuggestion ───────────────────────────────────────────────────────

func TestHeuristicSuggestion_SensitiveAlwaysDeny(t *testing.T) {
	c := pathContext{
		abs:         `/home/user/.ssh`,
		kind:        "dir",
		category:    "sensitive (SSOT credential surface)",
		exists:      true,
		isSensitive: true,
	}
	got := heuristicSuggestion(c)
	if got.mode != "deny" {
		t.Errorf("sensitive path: want deny, got %q", got.mode)
	}
	if got.reason == "" {
		t.Error("reason should be non-empty")
	}
}

func TestHeuristicSuggestion_MissingPathGetsSkip(t *testing.T) {
	c := pathContext{
		abs:    `/nonexistent/path/xyz`,
		kind:   "missing",
		exists: false,
	}
	got := heuristicSuggestion(c)
	if got.mode != "skip" {
		t.Errorf("missing path: want skip, got %q", got.mode)
	}
}

func TestHeuristicSuggestion_SystemPathGetsRO(t *testing.T) {
	c := pathContext{
		abs:      `C:\Windows\System32`,
		kind:     "dir",
		category: "system",
		exists:   true,
	}
	got := heuristicSuggestion(c)
	if got.mode != "ro" {
		t.Errorf("system path: want ro, got %q", got.mode)
	}
}

func TestHeuristicSuggestion_UserProfileGetsRW(t *testing.T) {
	c := pathContext{
		abs:      `/home/user/myproject`,
		kind:     "dir",
		category: "user-profile",
		exists:   true,
	}
	got := heuristicSuggestion(c)
	if got.mode != "rw" {
		t.Errorf("user-profile path: want rw, got %q", got.mode)
	}
}

func TestHeuristicSuggestion_OtherCategoryGetsRW(t *testing.T) {
	c := pathContext{
		abs:      `/mnt/data/tools`,
		kind:     "dir",
		category: "other",
		exists:   true,
	}
	got := heuristicSuggestion(c)
	if got.mode != "rw" {
		t.Errorf("other category: want rw, got %q", got.mode)
	}
}

// ── buildPathContext ──────────────────────────────────────────────────────────

func TestBuildPathContext_MissingPath(t *testing.T) {
	c := buildPathContext(`/nonexistent/dizgin-test-path-xyz-12345`)
	if c.exists {
		t.Error("exists: want false for nonexistent path")
	}
	if c.kind != "missing" {
		t.Errorf("kind: want missing, got %q", c.kind)
	}
}

func TestBuildPathContext_ExistingDir(t *testing.T) {
	dir := t.TempDir()
	c := buildPathContext(dir)
	if !c.exists {
		t.Error("exists: want true for temp dir")
	}
	if c.kind != "dir" {
		t.Errorf("kind: want dir, got %q", c.kind)
	}
	if c.size != 0 {
		t.Errorf("size: want 0 for dir, got %d", c.size)
	}
}

func TestBuildPathContext_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/testfile.txt"
	if err := os.WriteFile(path, []byte("hello world"), 0o600); err != nil {
		t.Fatalf("create test file: %v", err)
	}
	c := buildPathContext(path)
	if !c.exists {
		t.Error("exists: want true")
	}
	if c.kind != "file" {
		t.Errorf("kind: want file, got %q", c.kind)
	}
	if c.size <= 0 {
		t.Errorf("size: want >0 for non-empty file, got %d", c.size)
	}
}
