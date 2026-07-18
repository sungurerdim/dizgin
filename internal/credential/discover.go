// SPDX-License-Identifier: MIT

package credential

import (
	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/config"
)

// Discover scans the host for credentials according to cfg and the tool's
// known API key names. It returns the discovered credentials and any warning
// messages for credentials that could not be resolved.
func Discover(cfg *config.Config, apiKeyNames []string) ([]Credential, []string) {
	var creds []Credential
	var warnings []string

	// API keys.
	if cfg.Credential.SSHAgent || cfg.Credential.GitHubToken || len(cfg.Credential.APIKeys) > 0 {
		// Use configured key names if provided, otherwise scan all well-known prefixes.
		allowlist := cfg.Credential.APIKeys
		if len(apiKeyNames) > 0 {
			allowlist = merge(allowlist, apiKeyNames)
		}
		creds = append(creds, ScanAPIKeys(allowlist)...)
	}

	// GitHub token.
	if cfg.Credential.GitHubToken {
		if tok := DiscoverGitHubToken(); tok != "" {
			// Avoid duplication if GITHUB_TOKEN was already captured by ScanAPIKeys.
			if !hasCred(creds, "GITHUB_TOKEN") {
				creds = append(creds, Credential{
					Key:    "GITHUB_TOKEN",
					Value:  tok,
					Source: "github",
				})
			}
		} else {
			warnings = append(warnings, brand.Name+": credential: GitHub token not found (set GITHUB_TOKEN or run 'gh auth login')")
		}
	}

	// SSH agent.
	if cfg.Credential.SSHAgent {
		if env := SSHAgentEnv(); env != "" {
			creds = append(creds, Credential{
				Key:    "SSH_AUTH_SOCK",
				Value:  SSHAgentSocket(),
				Source: "ssh-agent",
			})
		} else {
			warnings = append(warnings, brand.Name+": credential: SSH agent not found (SSH_AUTH_SOCK not set)")
		}
	}

	// Git identity.
	if cfg.Credential.GitIdentity {
		id := DiscoverGitIdentity()
		for _, kv := range id.ToEnv() {
			k, v := SplitKV(kv)
			creds = append(creds, Credential{Key: k, Value: v, Source: "git"})
		}
	}

	// Platform-specific discovery (Keychain on macOS, secret-tool on Linux).
	creds = append(creds, platformDiscover(creds)...)

	// Secret providers (dotenv, vault) — only for API keys not yet found.
	providers := buildProviders(cfg, ".")
	if len(providers) > 0 {
		allKeys := merge(cfg.Credential.APIKeys, apiKeyNames)
		providerCreds := DiscoverFromProviders(providers, allKeys)
		for _, c := range providerCreds {
			if !hasCred(creds, c.Key) {
				creds = append(creds, c)
			}
		}
	}

	return creds, warnings
}

// buildProviders constructs the ordered list of secret providers from config.
func buildProviders(cfg *config.Config, workdir string) []SecretProvider {
	names := cfg.Credential.Providers
	if len(names) == 0 {
		return nil
	}
	var providers []SecretProvider
	for _, name := range names {
		switch name {
		case "dotenv":
			providers = append(providers, NewDotenvProvider(workdir))
		case "vault":
			providers = append(providers, NewVaultProvider(cfg.Credential.VaultMount, cfg.Credential.VaultPath))
		}
		// "env" is handled by ScanAPIKeys above
	}
	return providers
}

func merge(a, b []string) []string {
	seen := make(map[string]bool, len(a))
	for _, v := range a {
		seen[v] = true
	}
	result := make([]string, 0, len(a)+len(b))
	result = append(result, a...)
	for _, v := range b {
		if !seen[v] {
			result = append(result, v)
		}
	}
	return result
}

func hasCred(creds []Credential, key string) bool {
	for _, c := range creds {
		if c.Key == key {
			return true
		}
	}
	return false
}

// SplitKV splits a "KEY=VALUE" string into key and value parts.
func SplitKV(kv string) (key, val string) {
	for i := 0; i < len(kv); i++ {
		if kv[i] == '=' {
			return kv[:i], kv[i+1:]
		}
	}
	return kv, ""
}
