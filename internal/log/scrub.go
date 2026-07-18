// SPDX-License-Identifier: MIT

package log

import (
	"regexp"
	"strings"
)

// secretLikePattern matches the common shapes a secret takes in a log
// line: a key name (api_key, token, secret, password, with optional
// hyphen or underscore variants), optionally wrapped in quotes,
// followed by `=` or `:`, then the value (quoted or unquoted) up to
// the next whitespace, quote, or `}`.
//
// The match is intentionally loose — we'd rather over-redact a
// non-secret than miss a real one. Confirmed callers (env injection
// helpers, audit logger) build a list of patterns by category; this
// regex is the safety net.
var secretLikePattern = regexp.MustCompile(
	`(?i)(["']?(?:api[-_]?key|access[-_]?token|auth(?:orization)?|secret|password|passwd|pat|pwd|token|client[-_]?secret)["']?\s*[:=]\s*)("([^"]+)"|'([^']+)'|[^\s,}]+)`,
)

// bearerPattern matches HTTP Authorization-style "Bearer <token>"
// strings. Distinct from secretLikePattern because there is no `=`
// or `:` separator between "Bearer" and the token — just whitespace.
var bearerPattern = regexp.MustCompile(`(?i)(Bearer\s+)([A-Za-z0-9._\-]+)`)

// envLikePattern matches `KEY=VALUE` env-injection lines where the key
// matches the secret-like name set above. Caught separately because
// env exports often appear without quotes and with leading "export ".
var envLikePattern = regexp.MustCompile(
	`(?i)((?:^|\s)(?:export\s+)?([A-Z][A-Z0-9_]*(?:_(?:KEY|TOKEN|SECRET|PASSWORD|PWD|PAT))=))(\S+)`,
)

// ScrubSecrets returns s with the values of secret-shaped key/value
// pairs replaced by "[REDACTED]". Idempotent: applying twice is a
// no-op. Safe to call on user-controlled strings — the regex never
// dereferences anything outside the input.
//
// Use sites:
//   - log.Error / Warn / Info / Debug — every formatted message
//   - audit logger before flush to JSON-L
//   - panic recover handler before printing the goroutine dump
func ScrubSecrets(s string) string {
	if s == "" {
		return s
	}
	// Bearer pattern runs first because the secretLikePattern would
	// otherwise consume "Authorization: Bearer" and leave the JWT
	// dangling on its own — the bearer regex needs the literal
	// "Bearer" token to anchor.
	out := bearerPattern.ReplaceAllString(s, `${1}[REDACTED]`)
	out = secretLikePattern.ReplaceAllString(out, `${1}[REDACTED]`)
	out = envLikePattern.ReplaceAllString(out, `${1}[REDACTED]`)
	return out
}

// ScrubEnv returns env with any entry whose key matches the secret
// name set replaced by "KEY=[REDACTED]". Used by the panic recover
// path so a goroutine dump that includes os.Environ() does not leak
// the user's API keys to stderr / crash reports.
//
// Returns a fresh slice; the input is not mutated.
func ScrubEnv(env []string) []string {
	out := make([]string, len(env))
	for i, e := range env {
		idx := strings.IndexByte(e, '=')
		if idx <= 0 {
			out[i] = e
			continue
		}
		key := e[:idx]
		if isSecretEnvKey(key) {
			out[i] = key + "=[REDACTED]"
		} else {
			out[i] = e
		}
	}
	return out
}

// isSecretEnvKey reports whether key looks like an env var holding a
// secret. Conservative: matches any uppercase token ending in one of
// the common secret-suffix words.
func isSecretEnvKey(key string) bool {
	upper := strings.ToUpper(key)
	for _, suffix := range []string{
		"_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_PWD", "_PAT",
		"APIKEY", "AUTHKEY",
	} {
		if strings.HasSuffix(upper, suffix) {
			return true
		}
	}
	// Also catch bare "API_KEY", "SECRET", etc. when the key itself is
	// the entire word.
	switch upper {
	case "API_KEY", "TOKEN", "SECRET", "PASSWORD", "AUTH_TOKEN", "GITHUB_TOKEN":
		return true
	}
	return false
}
