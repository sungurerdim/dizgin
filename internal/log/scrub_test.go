// SPDX-License-Identifier: MIT

package log

import (
	"strings"
	"testing"
)

func TestScrubSecrets(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		shouldHide string
		shouldKeep string
	}{
		{
			name:       "API_KEY env shape",
			in:         "ANTHROPIC_API_KEY=sk-ant-12345abcdef",
			shouldHide: "sk-ant-12345abcdef",
			shouldKeep: "ANTHROPIC_API_KEY=",
		},
		{
			name:       "json-style token",
			in:         `{"token": "ghp_xxxxxxxxx"}`,
			shouldHide: "ghp_xxxxxxxxx",
			shouldKeep: `"token":`,
		},
		{
			name:       "bearer header",
			in:         "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload",
			shouldHide: "eyJhbGciOiJIUzI1NiJ9.payload",
			shouldKeep: "Authorization:",
		},
		{
			name:       "password=value",
			in:         "password=hunter2",
			shouldHide: "hunter2",
			shouldKeep: "password=",
		},
		{
			name:       "secret with quotes",
			in:         `client_secret = "abcdef123456"`,
			shouldHide: "abcdef123456",
			shouldKeep: "client_secret",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ScrubSecrets(c.in)
			if strings.Contains(got, c.shouldHide) {
				t.Errorf("ScrubSecrets did not redact %q in: %s", c.shouldHide, got)
			}
			if !strings.Contains(got, "[REDACTED]") {
				t.Errorf("ScrubSecrets missing [REDACTED] marker in: %s", got)
			}
			if !strings.Contains(got, c.shouldKeep) {
				t.Errorf("ScrubSecrets dropped non-secret context %q from: %s", c.shouldKeep, got)
			}
		})
	}
}

func TestScrubSecrets_LeavesPlainTextAlone(t *testing.T) {
	in := "restricted: stamping 23 mounts"
	if got := ScrubSecrets(in); got != in {
		t.Errorf("ScrubSecrets mutated benign text:\nin:  %s\nout: %s", in, got)
	}
}

func TestScrubSecrets_Idempotent(t *testing.T) {
	in := "ANTHROPIC_API_KEY=sk-secret"
	once := ScrubSecrets(in)
	twice := ScrubSecrets(once)
	if once != twice {
		t.Errorf("ScrubSecrets not idempotent:\nonce:  %s\ntwice: %s", once, twice)
	}
}

func TestScrubEnv(t *testing.T) {
	in := []string{
		"PATH=/usr/local/bin",
		"ANTHROPIC_API_KEY=sk-secret-1",
		"GITHUB_TOKEN=ghp_xxx",
		"USER=alice",
		"OPENAI_API_KEY=sk-secret-2",
		"DISPLAY=:0",
	}
	out := ScrubEnv(in)

	mustHide := []string{"sk-secret-1", "sk-secret-2", "ghp_xxx"}
	for _, h := range mustHide {
		joined := strings.Join(out, "\n")
		if strings.Contains(joined, h) {
			t.Errorf("ScrubEnv leaked %q: %s", h, joined)
		}
	}

	// DISPLAY/PATH/USER do not contain any of the secret-suffix tokens
	// (KEY/TOKEN/SECRET/PASSWORD/PWD/PAT) so they survive untouched.
	mustKeep := []string{"PATH=/usr/local/bin", "USER=alice", "DISPLAY=:0"}
	joined := strings.Join(out, "\n")
	for _, k := range mustKeep {
		if !strings.Contains(joined, k) {
			t.Errorf("ScrubEnv removed non-secret entry %q: %s", k, joined)
		}
	}
}

func TestIsSecretEnvKey(t *testing.T) {
	cases := []struct {
		key  string
		want bool
	}{
		{"ANTHROPIC_API_KEY", true},
		{"GITHUB_TOKEN", true},
		{"OPENAI_API_KEY", true},
		{"DB_PASSWORD", true},
		{"AWS_SECRET_ACCESS_KEY", true},
		{"PATH", false},
		{"HOME", false},
		{"USER", false},
		{"DISPLAY", false},
	}
	for _, c := range cases {
		if got := isSecretEnvKey(c.key); got != c.want {
			t.Errorf("isSecretEnvKey(%q) = %v, want %v", c.key, got, c.want)
		}
	}
}
