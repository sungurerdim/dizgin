// SPDX-License-Identifier: MIT

package config

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// captureStderr redirects os.Stderr for the duration of fn and returns
// what fn wrote there. parseProfile reports validation errors via
// fmt.Fprintf(os.Stderr, ...) — capturing the stream is the only
// behavioral surface we can assert against without restructuring the
// loader to return errors.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	prev := os.Stderr
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = prev })

	var buf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(&buf, r)
	}()

	fn()

	_ = w.Close()
	wg.Wait()
	return buf.String()
}

func TestParseProfile_StrictMode_RejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	yaml := `
name: typo-tester
version: 1
binary: anything
mcp_dir: /typo-here   # NOTE: real key is mcp_dirs (plural)
`
	if err := os.WriteFile(filepath.Join(dir, "typo.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	dest := make(map[string]ToolDef)
	stderr := captureStderr(t, func() { loadProfileDir(dir, dest) })

	if _, ok := dest["typo-tester"]; ok {
		t.Fatalf("strict-mode should have rejected the profile, but it loaded")
	}
	if !strings.Contains(stderr, "field mcp_dir not found") {
		t.Fatalf("expected stderr to flag unknown field mcp_dir, got: %s", stderr)
	}
}

func TestParseProfile_RejectsUnsupportedVersion(t *testing.T) {
	dir := t.TempDir()
	yaml := `
name: future-tool
version: 99
binary: future-tool
`
	if err := os.WriteFile(filepath.Join(dir, "future.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	dest := make(map[string]ToolDef)
	stderr := captureStderr(t, func() { loadProfileDir(dir, dest) })

	if _, ok := dest["future-tool"]; ok {
		t.Fatalf("unsupported version should have been rejected, but profile loaded")
	}
	if !strings.Contains(stderr, "unsupported profile version 99") {
		t.Fatalf("expected version mismatch in stderr, got: %s", stderr)
	}
}

func TestParseProfile_RejectsEmptyBinaryAndRuntime(t *testing.T) {
	dir := t.TempDir()
	yaml := `
name: inert-tool
version: 1
config_dirs:
  - "~/.something"
`
	if err := os.WriteFile(filepath.Join(dir, "inert.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	dest := make(map[string]ToolDef)
	stderr := captureStderr(t, func() { loadProfileDir(dir, dest) })

	if _, ok := dest["inert-tool"]; ok {
		t.Fatalf("inert profile (no binary, no runtime) should have been rejected, but loaded")
	}
	if !strings.Contains(stderr, "must declare either binary or runtime") {
		t.Fatalf("expected binary/runtime requirement in stderr, got: %s", stderr)
	}
}

func TestParseProfile_PreservesNetworkAllowlistData(t *testing.T) {
	// The bundled profiles use `network: { hosts: [...] }` which the old
	// lenient unmarshal silently dropped. Strict mode now requires the
	// field to exist on profileFile; this test pins the data to the
	// loaded profileFile so a future refactor that drops the parking
	// field surfaces in CI.
	dir := t.TempDir()
	yaml := `
name: net-aware
version: 1
binary: net-aware
network:
  hosts:
    - api.example.com
    - api.other.example.com
`
	if err := os.WriteFile(filepath.Join(dir, "net.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	dest := make(map[string]ToolDef)
	stderr := captureStderr(t, func() { loadProfileDir(dir, dest) })

	if stderr != "" {
		t.Fatalf("expected silent load with network field, got stderr: %s", stderr)
	}
	if _, ok := dest["net-aware"]; !ok {
		t.Fatalf("profile with network: field should load, but did not")
	}
	// The destination ToolDef does not yet expose Network, so the
	// strongest check is that strict-mode accepted the field. If/when
	// a future PR plumbs Network through ToolDef, extend the assertion
	// to inspect the stored hosts.
}

func TestParseProfile_AllBundledProfilesParseCleanly(t *testing.T) {
	// Regression: every embedded profile must survive strict-mode load
	// with zero stderr noise. This catches the next "silent unknown
	// field" footgun the moment it lands in profiles/.
	stderr := captureStderr(t, func() { LoadProfiles("") })

	if stderr != "" {
		t.Fatalf("bundled profiles produced stderr noise under strict mode:\n%s", stderr)
	}
	// Sanity: at least one well-known tool got loaded.
	names := KnownToolNames()
	found := false
	for _, n := range names {
		if n == "claude" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected at least the claude profile to be loaded; got %v", names)
	}
}
