// SPDX-License-Identifier: MIT

package credential

import (
	"strings"
	"testing"

	"github.com/sungurerdim/dizgin/internal/config"
)

// --- Sanitize tests ---

func TestSanitize_NUL(t *testing.T) {
	got := Sanitize("hello\x00world")
	if got != "helloworld" {
		t.Errorf("got %q, want %q", got, "helloworld")
	}
}

func TestSanitize_CRLFTrim(t *testing.T) {
	got := Sanitize("\r\nhello\r\n")
	if got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

func TestSanitize_SizeCap(t *testing.T) {
	big := strings.Repeat("A", maxCredentialBytes+100)
	got := Sanitize(big)
	if len(got) != maxCredentialBytes {
		t.Errorf("len=%d, want %d", len(got), maxCredentialBytes)
	}
}

func TestSanitize_Empty(t *testing.T) {
	if got := Sanitize(""); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestSanitizeEnv_Basic(t *testing.T) {
	got := SanitizeEnv("KEY=hello\x00world\r\n")
	if got != "KEY=helloworld" {
		t.Errorf("got %q", got)
	}
}

func TestSanitizeEnv_NoEquals(t *testing.T) {
	// Strings without '=' pass through unchanged.
	got := SanitizeEnv("NOEQUALS")
	if got != "NOEQUALS" {
		t.Errorf("got %q", got)
	}
}

// --- ScanAPIKeys tests ---

func TestScanAPIKeys_Allowlist(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	t.Setenv("OPENAI_API_KEY", "sk-openai-test")
	t.Setenv("UNRELATED_VAR", "should-not-appear")

	creds := ScanAPIKeys([]string{"ANTHROPIC_API_KEY"})
	if len(creds) != 1 {
		t.Fatalf("got %d creds, want 1", len(creds))
	}
	if creds[0].Key != "ANTHROPIC_API_KEY" {
		t.Errorf("key=%q", creds[0].Key)
	}
	if creds[0].Value != "sk-ant-test" {
		t.Errorf("value=%q", creds[0].Value)
	}
	if creds[0].Source != "env" {
		t.Errorf("source=%q", creds[0].Source)
	}
}

func TestScanAPIKeys_WellKnownPrefix(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-well-known")
	t.Setenv("UNRELATED_VAR", "nope")

	// Empty allowlist → scan all well-known prefixes.
	creds := ScanAPIKeys(nil)

	found := false
	for _, c := range creds {
		if c.Key == "ANTHROPIC_API_KEY" {
			found = true
		}
		if c.Key == "UNRELATED_VAR" {
			t.Error("UNRELATED_VAR should not be included")
		}
	}
	if !found {
		t.Error("ANTHROPIC_API_KEY not found in well-known scan")
	}
}

func TestScanAPIKeys_EmptyValue(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")

	creds := ScanAPIKeys([]string{"ANTHROPIC_API_KEY"})
	for _, c := range creds {
		if c.Key == "ANTHROPIC_API_KEY" {
			t.Error("empty-value credential should be excluded")
		}
	}
}

// --- ToEnv / ToEnvSlice tests ---

func TestCredentialToEnv(t *testing.T) {
	c := Credential{Key: "FOO", Value: "bar"}
	if got := c.ToEnv(); got != "FOO=bar" {
		t.Errorf("got %q", got)
	}
}

func TestToEnvSlice(t *testing.T) {
	creds := []Credential{
		{Key: "A", Value: "1"},
		{Key: "B", Value: "2"},
	}
	slice := ToEnvSlice(creds)
	if len(slice) != 2 || slice[0] != "A=1" || slice[1] != "B=2" {
		t.Errorf("got %v", slice)
	}
}

// --- SSHAgentEnv tests ---

func TestSSHAgentEnv_NotSet(t *testing.T) {
	// On non-Windows when SSH_AUTH_SOCK is unset, SSHAgentEnv returns "".
	t.Setenv("SSH_AUTH_SOCK", "")
	// We can't guarantee the socket path exists, so just ensure no panic.
	_ = SSHAgentEnv()
}

// --- GitIdentity tests ---

func TestGitIdentityToEnv_Empty(t *testing.T) {
	id := GitIdentity{}
	if env := id.ToEnv(); len(env) != 0 {
		t.Errorf("expected empty env, got %v", env)
	}
}

func TestGitIdentityToEnv_Full(t *testing.T) {
	id := GitIdentity{Name: "Alice", Email: "alice@example.com"}
	env := id.ToEnv()
	if len(env) != 4 {
		t.Fatalf("expected 4 entries, got %d: %v", len(env), env)
	}
	want := map[string]bool{
		"GIT_AUTHOR_NAME=Alice":                 true,
		"GIT_COMMITTER_NAME=Alice":              true,
		"GIT_AUTHOR_EMAIL=alice@example.com":    true,
		"GIT_COMMITTER_EMAIL=alice@example.com": true,
	}
	for _, e := range env {
		if !want[e] {
			t.Errorf("unexpected env entry: %q", e)
		}
	}
}

// --- merge / hasCred / splitKV helpers ---

func TestMerge(t *testing.T) {
	a := []string{"x", "y"}
	b := []string{"y", "z"}
	got := merge(a, b)
	if len(got) != 3 {
		t.Errorf("got %v", got)
	}
}

func TestHasCred(t *testing.T) {
	creds := []Credential{{Key: "FOO"}, {Key: "BAR"}}
	if !hasCred(creds, "FOO") {
		t.Error("hasCred: FOO not found")
	}
	if hasCred(creds, "BAZ") {
		t.Error("hasCred: BAZ should not be found")
	}
}

func TestSplitKV(t *testing.T) {
	k, v := SplitKV("KEY=VALUE")
	if k != "KEY" || v != "VALUE" {
		t.Errorf("got k=%q v=%q", k, v)
	}
	k2, v2 := SplitKV("NOEQUALS")
	if k2 != "NOEQUALS" || v2 != "" {
		t.Errorf("got k=%q v=%q", k2, v2)
	}
}

func TestSplitKV_MultipleEquals(t *testing.T) {
	k, v := SplitKV("KEY=VAL=UE")
	if k != "KEY" || v != "VAL=UE" {
		t.Errorf("got k=%q v=%q", k, v)
	}
}

func TestSplitKV_EmptyValue(t *testing.T) {
	k, v := SplitKV("KEY=")
	if k != "KEY" || v != "" {
		t.Errorf("got k=%q v=%q", k, v)
	}
}

func TestScanAPIKeys_WithEnv(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-test-123")
	t.Setenv("OPENAI_API_KEY", "sk-openai-456")

	creds := ScanAPIKeys(nil)
	found := make(map[string]bool)
	for _, c := range creds {
		found[c.Key] = true
	}
	if !found["ANTHROPIC_API_KEY"] {
		t.Error("ANTHROPIC_API_KEY not found")
	}
	if !found["OPENAI_API_KEY"] {
		t.Error("OPENAI_API_KEY not found")
	}
}

func TestScanAPIKeys_AllowlistCustomKey(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-test")
	t.Setenv("CUSTOM_KEY", "val")

	creds := ScanAPIKeys([]string{"CUSTOM_KEY"})
	found := make(map[string]bool)
	for _, c := range creds {
		found[c.Key] = true
	}
	if !found["CUSTOM_KEY"] {
		t.Error("CUSTOM_KEY should be in allowlist scan")
	}
}

func TestDiscoverGitHubToken_FromEnv(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_test123")
	tok := DiscoverGitHubToken()
	if tok == "" {
		t.Error("expected non-empty GitHub token from env")
	}
}

func TestDiscoverGitHubToken_NoEnv(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	// May still find token from gh CLI, so don't assert empty.
	// Just ensure no panic.
	_ = DiscoverGitHubToken()
}

func TestZeroString(t *testing.T) {
	// ZeroString uses unsafe to zero heap-allocated strings.
	// String literals live in read-only memory, so we must use a heap-allocated copy.
	s := string([]byte("secret_value"))
	ZeroString(s)
	// Can't reliably verify the original string is zeroed (Go may reuse memory),
	// but ensure no panic on heap strings.
}

func TestZeroCredentials(t *testing.T) {
	// Use heap-allocated strings to avoid writing to read-only memory.
	creds := []Credential{
		{Key: "A", Value: string([]byte("secret1"))},
		{Key: "B", Value: string([]byte("secret2"))},
	}
	ZeroCredentials(creds)
	for _, c := range creds {
		if c.Value != "" {
			t.Errorf("credential %s value not cleared", c.Key)
		}
	}
}

// --- Discover tests ---

func TestDiscover_APIKeysFromConfig(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-discover-test")
	// Clear GitHub/SSH env to avoid side effects.
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	t.Setenv("SSH_AUTH_SOCK", "")

	cfg := &config.Config{
		Credential: config.CredentialConfig{
			APIKeys: []string{"ANTHROPIC_API_KEY"},
		},
	}

	creds, warnings := Discover(cfg, nil)

	found := false
	for _, c := range creds {
		if c.Key == "ANTHROPIC_API_KEY" && c.Value == "sk-ant-discover-test" && c.Source == "env" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ANTHROPIC_API_KEY in discovered creds, got %v", creds)
	}
	// No warnings expected for this path.
	_ = warnings
}

func TestDiscover_GitHubTokenWarning(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	cfg := &config.Config{
		Credential: config.CredentialConfig{
			GitHubToken: true,
		},
	}

	_, warnings := Discover(cfg, nil)

	// gh CLI or git credential may still find a token, so only check warnings
	// if both env vars are empty and the system has no gh/git cred helper.
	// At minimum, ensure no panic.
	_ = warnings
}

func TestDiscover_EmptyConfig(t *testing.T) {
	cfg := &config.Config{}
	creds, warnings := Discover(cfg, nil)
	// With all credential flags off and no apiKeyNames, only platformDiscover runs.
	// Just verify no panic and no spurious warnings.
	_ = creds
	if len(warnings) != 0 {
		t.Errorf("expected no warnings for empty config, got %v", warnings)
	}
}

func TestDiscover_ToolAPIKeyNames(t *testing.T) {
	t.Setenv("MY_CUSTOM_KEY", "custom-val")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	t.Setenv("SSH_AUTH_SOCK", "")

	cfg := &config.Config{
		Credential: config.CredentialConfig{
			APIKeys: []string{"MY_CUSTOM_KEY"},
		},
	}

	creds, _ := Discover(cfg, []string{"MY_CUSTOM_KEY"})

	found := false
	for _, c := range creds {
		if c.Key == "MY_CUSTOM_KEY" && c.Value == "custom-val" {
			found = true
		}
	}
	if !found {
		t.Error("expected MY_CUSTOM_KEY from tool apiKeyNames")
	}
}

// --- DiscoverGitIdentity tests ---

func TestDiscoverGitIdentity_WithEnv(t *testing.T) {
	// DiscoverGitIdentity reads from `git config --global`, not env vars.
	// We can't reliably mock that, so just ensure no panic and valid shape.
	id := DiscoverGitIdentity()
	// Name and Email may or may not be set depending on the host.
	env := id.ToEnv()
	for _, e := range env {
		if !strings.Contains(e, "=") {
			t.Errorf("ToEnv entry missing '=': %q", e)
		}
	}
}

func TestGitIdentityToEnv_NameOnly(t *testing.T) {
	id := GitIdentity{Name: "Bob", Email: ""}
	env := id.ToEnv()
	if len(env) != 2 {
		t.Fatalf("expected 2 entries for name-only, got %d: %v", len(env), env)
	}
	for _, e := range env {
		if !strings.Contains(e, "Bob") {
			t.Errorf("expected 'Bob' in entry: %q", e)
		}
	}
}

func TestGitIdentityToEnv_EmailOnly(t *testing.T) {
	id := GitIdentity{Name: "", Email: "bob@example.com"}
	env := id.ToEnv()
	if len(env) != 2 {
		t.Fatalf("expected 2 entries for email-only, got %d: %v", len(env), env)
	}
	for _, e := range env {
		if !strings.Contains(e, "bob@example.com") {
			t.Errorf("expected email in entry: %q", e)
		}
	}
}

// --- ScanAPIKeys deduplication ---

func TestScanAPIKeys_Deduplication(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-dedup-test")

	// Pass ANTHROPIC_API_KEY in allowlist — it also matches well-known prefix.
	// With a non-empty allowlist, only allowlist keys are scanned (no well-known fallback),
	// so each key should appear at most once.
	creds := ScanAPIKeys([]string{"ANTHROPIC_API_KEY"})

	count := 0
	for _, c := range creds {
		if c.Key == "ANTHROPIC_API_KEY" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 ANTHROPIC_API_KEY, got %d", count)
	}
}

// --- Sanitize edge cases ---

func TestSanitize_OnlyWhitespace(t *testing.T) {
	// Sanitize trims \r\n but not spaces/tabs — verify behavior.
	got := Sanitize("\r\n\r\n")
	if got != "" {
		t.Errorf("got %q, want empty for CR/LF only input", got)
	}

	// Spaces and tabs are NOT trimmed by Sanitize (it only trims \r\n).
	got2 := Sanitize("   \t  ")
	if got2 != "   \t  " {
		t.Errorf("got %q, want %q (spaces preserved)", got2, "   \t  ")
	}
}

func TestSanitize_Unicode(t *testing.T) {
	input := "sk-\u00e9\u00e8\u00ea\u4e16\u754c\U0001f600"
	got := Sanitize(input)
	if got != input {
		t.Errorf("unicode not preserved: got %q, want %q", got, input)
	}
}

// --- SanitizeEnv edge cases ---

func TestSanitizeEnv_EmptyKey(t *testing.T) {
	// KEY= format: empty value after '='.
	got := SanitizeEnv("MYKEY=")
	if got != "MYKEY=" {
		t.Errorf("got %q, want %q", got, "MYKEY=")
	}
}

func TestSanitizeEnv_EmptyKeyName(t *testing.T) {
	// =VALUE format: empty key name (edge case).
	got := SanitizeEnv("=somevalue")
	if got != "=somevalue" {
		t.Errorf("got %q, want %q", got, "=somevalue")
	}
}

// --- ToEnvSlice edge cases ---

func TestToEnvSlice_Empty(t *testing.T) {
	slice := ToEnvSlice([]Credential{})
	if slice == nil {
		t.Error("expected non-nil empty slice, got nil")
	}
	if len(slice) != 0 {
		t.Errorf("expected 0 entries, got %d", len(slice))
	}
}

func TestToEnvSlice_Nil(t *testing.T) {
	slice := ToEnvSlice(nil)
	// nil input produces a non-nil but empty slice (make(..., 0)).
	if len(slice) != 0 {
		t.Errorf("expected 0 entries for nil input, got %d", len(slice))
	}
}
