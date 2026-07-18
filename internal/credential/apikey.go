// SPDX-License-Identifier: MIT

package credential

import (
	"os"
	"strings"
)

// wellKnownAPIKeyPrefixes lists environment variable name prefixes that are
// candidates for API key injection. The scan is case-insensitive.
var wellKnownAPIKeyPrefixes = []string{
	"ANTHROPIC_",
	"OPENAI_",
	"GEMINI_",
	"GOOGLE_",
	"AZURE_OPENAI_",
	"GROQ_",
	"MISTRAL_",
	"COHERE_",
	"HUGGINGFACE_",
	"TOGETHER_",
	"PERPLEXITY_",
	"FIREWORKS_",
}

// ScanAPIKeys returns all API-key-like environment variables from the current
// process environment. It honours an optional allowlist: if allowlist is
// non-empty, only variables whose names appear in it are returned.
func ScanAPIKeys(allowlist []string) []Credential {
	allowSet := make(map[string]bool, len(allowlist))
	for _, k := range allowlist {
		allowSet[strings.ToUpper(k)] = true
	}

	var creds []Credential
	for _, kv := range os.Environ() {
		idx := strings.IndexByte(kv, '=')
		if idx < 0 {
			continue
		}
		key := kv[:idx]
		val := kv[idx+1:]

		// If there's an allowlist, only take explicitly requested keys.
		if len(allowSet) > 0 {
			if !allowSet[strings.ToUpper(key)] {
				continue
			}
		} else {
			// No allowlist → include all well-known API key prefixes.
			if !hasWellKnownPrefix(key) {
				continue
			}
		}

		val = Sanitize(val)
		if val == "" {
			continue
		}
		creds = append(creds, Credential{Key: key, Value: val, Source: "env"})
	}
	return creds
}

func hasWellKnownPrefix(key string) bool {
	upper := strings.ToUpper(key)
	for _, prefix := range wellKnownAPIKeyPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}
