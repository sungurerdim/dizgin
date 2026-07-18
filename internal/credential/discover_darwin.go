// SPDX-License-Identifier: MIT

//go:build darwin

package credential

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// PlatformConfigDirs returns macOS-specific configuration directories that
// may contain credentials for AI tools. These are used for mount planning.
func PlatformConfigDirs() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	candidates := []string{
		filepath.Join(home, ".anthropic"),
		filepath.Join(home, ".config"),
		filepath.Join(home, "Library", "Application Support", "Claude"),
		filepath.Join(home, "Library", "Application Support", "claude-code"),
		filepath.Join(home, "Library", "Application Support", "OpenAI"),
		filepath.Join(home, ".codex"),
		filepath.Join(home, ".aider"),
		filepath.Join(home, ".gemini"),
	}

	var existing []string
	for _, d := range candidates {
		if _, err := os.Stat(d); err == nil {
			existing = append(existing, d)
		}
	}
	return existing
}

// DiscoverKeychainSecret looks up a secret stored in the macOS Keychain using
// the `security` command-line tool. Returns an empty string on failure.
// service is the keychain service name, account is the account name.
func DiscoverKeychainSecret(service, account string) string {
	args := []string{
		"find-generic-password",
		"-s", service,
		"-a", account,
		"-w", // print password only
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "security", args...).Output()
	if err != nil {
		return ""
	}
	return Sanitize(strings.TrimSpace(string(out)))
}

// ScanKeychainAPIKeys attempts to retrieve well-known API keys from the macOS
// Keychain. This supplements environment variable discovery.
func ScanKeychainAPIKeys() []Credential {
	type entry struct {
		service string
		account string
		envKey  string
	}

	// Well-known Keychain entries for AI tools.
	entries := []entry{
		{"ANTHROPIC_API_KEY", "anthropic", "ANTHROPIC_API_KEY"},
		{"OPENAI_API_KEY", "openai", "OPENAI_API_KEY"},
		{"GEMINI_API_KEY", "google", "GEMINI_API_KEY"},
	}

	var creds []Credential
	for _, e := range entries {
		val := DiscoverKeychainSecret(e.service, e.account)
		if val != "" {
			creds = append(creds, Credential{
				Key:    e.envKey,
				Value:  val,
				Source: "keychain",
			})
		}
	}
	return creds
}

// PlatformDiscover performs macOS-specific credential discovery (Keychain).
// It returns discovered credentials that are not already present in existing.
func PlatformDiscover(existing []Credential) []Credential {
	keychainCreds := ScanKeychainAPIKeys()
	var extra []Credential
	for _, c := range keychainCreds {
		if !hasCred(existing, c.Key) {
			extra = append(extra, c)
		}
	}
	return extra
}
