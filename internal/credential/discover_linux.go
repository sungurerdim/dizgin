// SPDX-License-Identifier: MIT

//go:build linux

package credential

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// PlatformConfigDirs returns Linux-specific configuration directories that
// may contain credentials for AI tools. These are used for mount planning.
func PlatformConfigDirs() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		configHome = filepath.Join(home, ".config")
	}

	candidates := []string{
		filepath.Join(home, ".anthropic"),
		configHome,
		filepath.Join(home, ".codex"),
		filepath.Join(home, ".aider"),
		filepath.Join(home, ".gemini"),
		filepath.Join(configHome, "claude"),
		filepath.Join(configHome, "openai"),
	}

	var existing []string
	for _, d := range candidates {
		if _, err := os.Stat(d); err == nil {
			existing = append(existing, d)
		}
	}
	return existing
}

// DiscoverSecretToolSecret looks up a secret from the GNOME Keyring / libsecret
// using the `secret-tool` command-line utility. Returns an empty string on failure.
func DiscoverSecretToolSecret(attribute, value string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "secret-tool", "lookup", attribute, value).Output()
	if err != nil {
		return ""
	}
	return Sanitize(strings.TrimSpace(string(out)))
}

// ScanSecretToolAPIKeys attempts to retrieve well-known API keys from the
// GNOME Keyring via secret-tool. This supplements environment variable discovery.
func ScanSecretToolAPIKeys() []Credential {
	type entry struct {
		attribute string
		value     string
		envKey    string
	}

	// Common secret-tool attribute/value pairs used by AI tool installers.
	entries := []entry{
		{"service", "ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"},
		{"service", "OPENAI_API_KEY", "OPENAI_API_KEY"},
		{"service", "GEMINI_API_KEY", "GEMINI_API_KEY"},
	}

	var creds []Credential
	for _, e := range entries {
		val := DiscoverSecretToolSecret(e.attribute, e.value)
		if val != "" {
			creds = append(creds, Credential{
				Key:    e.envKey,
				Value:  val,
				Source: "secret-tool",
			})
		}
	}
	return creds
}

// PlatformDiscover performs Linux-specific credential discovery (GNOME Keyring).
// It returns discovered credentials that are not already present in existing.
func PlatformDiscover(existing []Credential) []Credential {
	keychainCreds := ScanSecretToolAPIKeys()
	var extra []Credential
	for _, c := range keychainCreds {
		if !hasCred(existing, c.Key) {
			extra = append(extra, c)
		}
	}
	return extra
}
