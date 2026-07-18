// SPDX-License-Identifier: MIT

package security

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestIsRiskyPath_RegistryHives(t *testing.T) {
	cases := []string{
		`C:\Windows\System32\config\SAM`,
		`C:\Windows\System32\config\SECURITY`,
		`c:\windows\system32\config\SYSTEM`,
		`C:\Windows\System32\config\RegBack\SAM`,
	}
	for _, p := range cases {
		risky, reason := IsRiskyPath(p)
		if !risky {
			t.Errorf("IsRiskyPath(%q) = false, want true", p)
		}
		if reason != RiskSystemSecurity {
			t.Errorf("IsRiskyPath(%q) reason = %q, want %q", p, reason, RiskSystemSecurity)
		}
	}
}

func TestIsRiskyPath_NTUserHive(t *testing.T) {
	p := `C:\Users\Test\NTUSER.DAT`
	risky, reason := IsRiskyPath(p)
	if !risky || reason != RiskSystemSecurity {
		t.Errorf("IsRiskyPath(%q) = (%v, %q), want (true, %q)", p, risky, reason, RiskSystemSecurity)
	}
}

func TestIsRiskyPath_SSHKeys(t *testing.T) {
	cases := []string{
		`C:\Users\test\.ssh\id_rsa`,
		`C:\Users\test\.ssh\id_ed25519`,
		`C:\Users\test\.ssh\my_work_rsa`,
		`/home/alice/.ssh/id_ecdsa`,
		`/home/alice/.ssh/identity`,
	}
	for _, p := range cases {
		risky, reason := IsRiskyPath(p)
		if !risky {
			t.Errorf("IsRiskyPath(%q) = false, want true", p)
		}
		if reason != RiskSSHPrivateKey {
			t.Errorf("IsRiskyPath(%q) reason = %q, want %q", p, reason, RiskSSHPrivateKey)
		}
	}
}

func TestIsRiskyPath_SSHPublicKeys_NotDenied(t *testing.T) {
	// Public keys are safe — known_hosts and .pub files should pass through.
	cases := []string{
		`C:\Users\test\.ssh\id_rsa.pub`,
		`C:\Users\test\.ssh\known_hosts`,
		`C:\Users\test\.ssh\config`,
	}
	// Only assert the SSH rule does not match — another rule (e.g. "other
	// user profile") may still flag the path if the test host is not user
	// "test". The point of this test is that we do not *mistake* a public
	// key or known_hosts file for a private key.
	for _, p := range cases {
		risky, reason := IsRiskyPath(p)
		if risky && reason == RiskSSHPrivateKey {
			t.Errorf("IsRiskyPath(%q) flagged as private SSH key (reason = %q)", p, reason)
		}
	}
}

func TestIsRiskyPath_CloudCreds(t *testing.T) {
	cases := []struct {
		p      string
		reason RiskyReason
	}{
		{`C:\Users\test\.aws\credentials`, RiskCloudCreds},
		{`/home/alice/.aws/credentials`, RiskCloudCreds},
		{`C:\Users\test\.azure\accessTokens.json`, RiskCloudCreds},
		{`/home/alice/.config/gcloud/application_default_credentials.json`, RiskCloudCreds},
	}
	for _, c := range cases {
		risky, reason := IsRiskyPath(c.p)
		if !risky || reason != c.reason {
			t.Errorf("IsRiskyPath(%q) = (%v, %q), want (true, %q)", c.p, risky, reason, c.reason)
		}
	}
}

func TestIsRiskyPath_CredentialStores(t *testing.T) {
	cases := []string{
		`C:\Users\Sungur\AppData\Local\Microsoft\Credentials\ABCDEF`,
		`C:\Users\Sungur\AppData\Roaming\Microsoft\Credentials\foo`,
		`C:\Users\Sungur\AppData\Local\Microsoft\Vault\Policy.vpol`,
		`/home/alice/.gnupg/secring.gpg`,
	}
	for _, p := range cases {
		if risky, _ := IsRiskyPath(p); !risky {
			t.Errorf("IsRiskyPath(%q) = false, want true", p)
		}
	}
}

func TestIsRiskyPath_BrowserSessions(t *testing.T) {
	cases := []string{
		`C:\Users\Sungur\AppData\Local\Google\Chrome\User Data\Default\Cookies`,
		`C:\Users\Sungur\AppData\Local\Microsoft\Edge\User Data\Default\Cookies-journal`,
		`C:\Users\Sungur\AppData\Roaming\Mozilla\Firefox\Profiles\abc.default\cookies.sqlite`,
	}
	for _, p := range cases {
		risky, reason := IsRiskyPath(p)
		if !risky {
			t.Errorf("IsRiskyPath(%q) = false, want true", p)
		}
		if reason != RiskBrowserSession {
			t.Errorf("IsRiskyPath(%q) reason = %q, want %q", p, reason, RiskBrowserSession)
		}
	}
}

func TestIsRiskyPath_PasswordManagers(t *testing.T) {
	cases := []string{
		`C:\Users\Sungur\Documents\personal.kdbx`,
		`C:\Users\Sungur\AppData\Roaming\Bitwarden\data.json`,
	}
	for _, p := range cases {
		risky, reason := IsRiskyPath(p)
		if !risky {
			t.Errorf("IsRiskyPath(%q) = false, want true", p)
		}
		if reason != RiskPasswordManager {
			t.Errorf("IsRiskyPath(%q) reason = %q", p, reason)
		}
	}
}

func TestIsRiskyPath_OtherUserProfile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Setenv("USERNAME", "Sungur")
	} else {
		t.Setenv("USER", "alice")
	}
	resetCurrentUserCache()
	t.Cleanup(resetCurrentUserCache)

	if runtime.GOOS == "windows" {
		// Different Windows user → risky.
		risky, reason := IsRiskyPath(`C:\Users\Bob\Documents\foo.txt`)
		if !risky {
			t.Error(`C:\Users\Bob\... should be risky when running as Sungur`)
		}
		if reason != RiskOtherUserProfile {
			t.Errorf("reason = %q, want %q", reason, RiskOtherUserProfile)
		}
		// Same user → not risky.
		if risky, _ := IsRiskyPath(`C:\Users\Sungur\Documents\foo.txt`); risky {
			t.Error(`C:\Users\Sungur\... should NOT be risky for user Sungur`)
		}
	} else {
		// POSIX: different /home user → risky.
		risky, reason := IsRiskyPath(`/home/bob/Documents/foo.txt`)
		if !risky {
			t.Error("/home/bob/... should be risky when running as alice")
		}
		if reason != RiskOtherUserProfile {
			t.Errorf("reason = %q, want %q", reason, RiskOtherUserProfile)
		}
		// Same user → not risky.
		if risky, _ := IsRiskyPath(`/home/alice/Documents/foo.txt`); risky {
			t.Error("/home/alice/... should NOT be risky for user alice")
		}
	}

	// Public shared profile → not risky on either platform.
	if risky, _ := IsRiskyPath(`C:\Users\Public\Documents\readme.txt`); risky {
		t.Error(`C:\Users\Public\... should not be risky (shared profile)`)
	}
}

func TestIsRiskyPath_RejectsRelativePaths(t *testing.T) {
	cases := []string{
		``,
		`relative/path`,
		`..\evil`,
		`not-a-path`,
	}
	for _, p := range cases {
		if risky, _ := IsRiskyPath(p); risky {
			t.Errorf("IsRiskyPath(%q) = true, want false for relative input", p)
		}
	}
}

func TestUserDeny_AppendAndMatch(t *testing.T) {
	dir := t.TempDir()
	SetUserDenyDir(dir)
	t.Cleanup(func() { SetUserDenyDir("") })

	path := `C:\Secret\Project\*`
	if err := AppendUserDeny("claude", path, "internal repo"); err != nil {
		t.Fatalf("AppendUserDeny: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(dir, "claude.yaml"))
	if err != nil {
		t.Fatalf("read deny file: %v", err)
	}
	if !strings.Contains(string(body), "Secret") {
		t.Errorf("deny file missing entry: %s", string(body))
	}

	if denied, _ := IsUserDenied(`C:\Secret\Project\README.md`); !denied {
		t.Error("user deny rule did not match concrete path under wildcard")
	}

	// Idempotent re-append.
	if err := AppendUserDeny("claude", path, "internal repo"); err != nil {
		t.Fatalf("AppendUserDeny (second call): %v", err)
	}
}
