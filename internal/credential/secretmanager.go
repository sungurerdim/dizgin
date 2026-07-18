// SPDX-License-Identifier: MIT

package credential

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// SecretProvider is the interface for external credential sources.
// Each provider is queried in order; the first non-empty value wins.
type SecretProvider interface {
	// Name returns a human-readable identifier for logging.
	Name() string
	// Get retrieves the value for key. Returns ("", nil) if not found.
	Get(key string) (string, error)
}

// DotenvProvider reads credentials from .env files in the workdir.
// Files are checked in order: .env.local, .env (last write wins).
// Permissions are validated: files must be 0600 or 0400.
type DotenvProvider struct {
	workdir string
}

// NewDotenvProvider creates a provider that reads from .env files in workdir.
func NewDotenvProvider(workdir string) *DotenvProvider {
	return &DotenvProvider{workdir: workdir}
}

func (p *DotenvProvider) Name() string { return "dotenv" }

func (p *DotenvProvider) Get(key string) (string, error) {
	merged := make(map[string]string)
	// Load in order: .env first, then .env.local (local overrides base).
	for _, name := range []string{".env", ".env.local"} {
		path := filepath.Join(p.workdir, name)
		vals, err := loadDotenvFile(path)
		if err != nil {
			continue // file not found or permission error — skip silently
		}
		for k, v := range vals {
			merged[k] = v
		}
	}
	if v, ok := merged[key]; ok {
		return v, nil
	}
	return "", nil
}

// loadDotenvFile loads a single .env file after validating its permissions.
// Returns an empty map (not an error) if the file doesn't exist.
func loadDotenvFile(path string) (map[string]string, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("dotenv: stat %q: %w", path, err)
	}
	// Warn if the file has overly permissive permissions on Unix.
	// On Windows, os.FileMode permission bits are minimal (0o666 for all files)
	// so the check would always fire — skip it entirely.
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			fmt.Fprintf(os.Stderr, brand.Name+": warning: %q has loose permissions (%o); consider chmod 600\n", path, perm)
		}
	}
	return parseDotenvFile(path)
}

// parseDotenvFile reads a .env file and returns its KEY=VALUE pairs.
// Blank lines and lines starting with '#' are ignored.
// Values may be optionally wrapped in single or double quotes (stripped).
func parseDotenvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("dotenv: open %q: %w", path, err)
	}
	defer f.Close() //nolint:errcheck

	result := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue // no '=' — not a valid KEY=VALUE line
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') ||
				(val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		if key != "" {
			result[key] = val
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("dotenv: read %q: %w", path, err)
	}
	return result, nil
}

// VaultProvider reads credentials from HashiCorp Vault via the vault CLI.
// VAULT_ADDR and VAULT_TOKEN (or ~/.vault-token) must be set in the environment.
// If the vault binary is not in PATH, Get always returns ("", nil).
type VaultProvider struct {
	mountPath  string // KV mount path, e.g. "secret" for kv-v2
	secretPath string // Secret path, e.g. "myapp/config"
}

// NewVaultProvider creates a provider that reads from the given Vault KV path.
// mountPath is the KV engine mount (default "secret"); secretPath is the path
// within the mount.
func NewVaultProvider(mountPath, secretPath string) *VaultProvider {
	if mountPath == "" {
		mountPath = "secret"
	}
	return &VaultProvider{mountPath: mountPath, secretPath: secretPath}
}

func (p *VaultProvider) Name() string { return "vault" }

func (p *VaultProvider) Get(key string) (string, error) {
	vaultBin, err := exec.LookPath("vault")
	if err != nil {
		return "", nil // vault not installed — skip silently
	}
	if os.Getenv("VAULT_ADDR") == "" {
		return "", nil // no server configured — skip silently
	}

	// vault kv get -field=<key> <mount>/<path>
	fullPath := p.mountPath + "/" + p.secretPath
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, vaultBin, "kv", "get", "-field="+key, fullPath)
	// Minimal env: only PATH, VAULT_* vars, and HOME/USERPROFILE.
	// Passing the full os.Environ() would leak unrelated secrets into the subprocess.
	var vaultEnv []string
	for _, kv := range os.Environ() {
		k := kv
		if idx := strings.IndexByte(kv, '='); idx >= 0 {
			k = kv[:idx]
		}
		switch {
		case k == "PATH", k == "HOME", k == "USERPROFILE",
			strings.HasPrefix(k, "VAULT_"):
			vaultEnv = append(vaultEnv, kv)
		}
	}
	cmd.Env = vaultEnv

	out, cmdErr := cmd.Output()
	if cmdErr != nil {
		// Key not found or Vault unreachable — treat as not-found.
		return "", nil
	}
	value := strings.TrimSpace(string(out))
	return value, nil
}

// DiscoverFromProviders queries the given providers for each key in keys.
// Returns a slice of Credentials sourced from the providers.
// Keys already present in the environment are skipped.
func DiscoverFromProviders(providers []SecretProvider, keys []string) []Credential {
	var found []Credential
	for _, key := range keys {
		// Skip if already set in the environment.
		if os.Getenv(key) != "" {
			continue
		}
		for _, p := range providers {
			val, err := p.Get(key)
			if err != nil {
				fmt.Fprintf(os.Stderr, brand.Name+": %s: %v\n", p.Name(), err)
				continue
			}
			if val == "" {
				continue
			}
			found = append(found, Credential{
				Key:    key,
				Value:  Sanitize(val),
				Source: p.Name(),
			})
			break // first provider wins
		}
	}
	return found
}
