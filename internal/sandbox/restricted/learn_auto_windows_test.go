// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import "testing"

// TestAutoGrantSafe is the security-critical guard: a credential-SSOT
// path must NEVER be auto-grant eligible, while ordinary system/user
// paths are. Pins the invariant that R1 is never auto-relaxed.
func TestAutoGrantSafe(t *testing.T) {
	const home = `C:\Users\testuser`
	t.Setenv("USERPROFILE", home)

	cases := []struct {
		path string
		safe bool
	}{
		{`C:\Users\testuser\.ssh\id_rsa`, false},                  // sensitive — never auto
		{`C:\Users\testuser\.aws\credentials`, false},             // sensitive
		{`C:\Users\testuser\.azure\msal_token_cache.json`, false}, // sensitive (Phase 2)
		{`C:\Windows\System32\drivers\etc\hosts`, true},           // system, non-sensitive
		{`C:\Users\testuser\projects\foo\config.json`, true},      // user, non-sensitive
		{`C:\Users\testuser\.claude\settings.json`, true},         // tool config, non-sensitive
	}
	for _, c := range cases {
		if got := autoGrantSafe(c.path); got != c.safe {
			t.Errorf("autoGrantSafe(%q) = %v, want %v", c.path, got, c.safe)
		}
	}
}

func TestSplitDeniedPaths(t *testing.T) {
	const home = `C:\Users\testuser`
	t.Setenv("USERPROFILE", home)

	paths := []string{
		`C:\Users\testuser\.ssh\config`,        // sensitive
		`C:\Windows\System32\foo.dll`,          // safe
		`C:\Users\testuser\.gnupg\secring.gpg`, // sensitive
		`C:\Users\testuser\work\data.txt`,      // safe
	}
	safe, sensitive := splitDeniedPaths(paths)
	if len(safe) != 2 {
		t.Errorf("safe = %v, want 2", safe)
	}
	if len(sensitive) != 2 {
		t.Errorf("sensitive = %v, want 2", sensitive)
	}
}

func TestOverridesContainFold(t *testing.T) {
	o := Overrides{
		RO: []string{`C:\Windows\System32\foo.dll`},
		RW: []string{`C:\Users\testuser\work`},
	}
	if !overridesContainFold(o, `c:\windows\system32\FOO.dll`) {
		t.Error("expected case-insensitive match on existing RO entry")
	}
	if !overridesContainFold(o, `C:\Users\testuser\work`) {
		t.Error("expected match on existing RW entry")
	}
	if overridesContainFold(o, `C:\Users\testuser\other`) {
		t.Error("unexpected match on absent path")
	}
}
