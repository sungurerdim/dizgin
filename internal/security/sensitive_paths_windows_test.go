// SPDX-License-Identifier: MIT

//go:build windows

package security

import (
	"strings"
	"testing"
)

// TestSensitiveDenyPathsExpanded is the Faz 2 acceptance test for the
// SSOT contents. Asserts:
//  1. The list has ≥11 entries (plan minimum — DPAPI + browser stores
//     bring the count to 15).
//  2. Every expanded path is anchored to the supplied userProfile.
//  3. The high-priority credential surfaces (.ssh, .aws/credentials,
//     .gnupg, .netrc, .docker, .kube) all appear.
//
// A regression that drops one of these (or fat-fingers a typo so the
// stamp loop silently skips it on os.IsNotExist) is caught here.
func TestSensitiveDenyPathsExpanded(t *testing.T) {
	const home = `C:\Users\testuser`

	paths := SensitiveDenyPaths(home)
	if len(paths) < 11 {
		t.Fatalf("expected ≥11 sensitive paths, got %d: %v", len(paths), paths)
	}
	for _, p := range paths {
		if !strings.HasPrefix(strings.ToLower(p), strings.ToLower(home)) {
			t.Errorf("path not under userProfile %q: %q", home, p)
		}
	}

	mustHaveSubstrings := []string{
		`.ssh`,
		`.aws\credentials`,
		`.aws\config`,
		`.gnupg`,
		`.netrc`,
		`.docker\config.json`,
		`.kube`,
		`.git-credentials`,
		`.azure`,                             // Azure CLI token cache
		`.config\gcloud`,                     // GCP ADC + access tokens
		`.terraform.d\credentials.tfrc.json`, // Terraform Cloud API token
		`Crypto`,                             // CryptoAPI RSA/DSS private key store
		`Protect`,                            // DPAPI master keys + CREDHIST
		`Credentials`,                        // Win Credential Manager backing
		`Chrome`,
		`Edge`,
		`Firefox`,
	}
	joined := strings.Join(paths, "|")
	for _, m := range mustHaveSubstrings {
		if !strings.Contains(joined, m) {
			t.Errorf("missing sensitive path containing %q in: %v", m, paths)
		}
	}
}

func TestSensitiveDenyPaths_emptyHome(t *testing.T) {
	if got := SensitiveDenyPaths(""); got != nil {
		t.Errorf("expected nil for empty userProfile, got %v", got)
	}
}

// TestIsSensitiveDeny exercises the SSOT classifier with explicit cases
// from the plan. The contract: a sensitive subtree returns true,
// non-sensitive user paths return false, system + empty inputs return
// false.
func TestIsSensitiveDeny(t *testing.T) {
	const home = `C:\Users\testuser`

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"ssh root", `C:\Users\testuser\.ssh`, true},
		{"ssh private key", `C:\Users\testuser\.ssh\id_rsa`, true},
		{"ssh deep file", `C:\Users\testuser\.ssh\config.d\foo`, true},
		{"aws credentials file", `C:\Users\testuser\.aws\credentials`, true},
		{"gnupg root", `C:\Users\testuser\.gnupg`, true},
		{"docker config file", `C:\Users\testuser\.docker\config.json`, true},
		{"CryptoAPI RSA store", `C:\Users\testuser\AppData\Roaming\Microsoft\Crypto\foo`, true},
		{"DPAPI master keys (Protect)", `C:\Users\testuser\AppData\Roaming\Microsoft\Protect\S-1-5-21-foo\bar`, true},
		{"DPAPI CREDHIST", `C:\Users\testuser\AppData\Roaming\Microsoft\Protect\CREDHIST`, true},
		{"chrome cookies", `C:\Users\testuser\AppData\Local\Google\Chrome\User Data\Default\Cookies`, true},
		{"azure root", `C:\Users\testuser\.azure`, true},
		{"azure token cache", `C:\Users\testuser\.azure\msal_token_cache.json`, true},
		{"gcloud ADC", `C:\Users\testuser\.config\gcloud\application_default_credentials.json`, true},
		{"terraform cloud token", `C:\Users\testuser\.terraform.d\credentials.tfrc.json`, true},

		{"claude config dir — RW expected", `C:\Users\testuser\.claude`, false},
		{"adjacent name .azure-backup != .azure", `C:\Users\testuser\.azure-backup`, false},
		{"terraform.d dir without the token file", `C:\Users\testuser\.terraform.d\plugins`, false},
		{"gcloud sibling .config\\gh is its own entry, .config root not denied", `C:\Users\testuser\.config`, false},
		{"claude config file", `C:\Users\testuser\.claude\settings.json`, false},
		{"project workdir", `C:\Users\testuser\projects\foo`, false},
		{"system path", `C:\Windows\System32`, false},
		{"adjacent but different file (.sshd-config != .ssh)", `C:\Users\testuser\.sshd-config`, false},
		{"empty path", "", false},
		{"adjacent name within .aws (case-insensitive boundary)", `C:\Users\testuser\.aws-backup`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSensitiveDenyAt(tt.path, home)
			if got != tt.want {
				t.Errorf("IsSensitiveDenyAt(%q, %q) = %v, want %v",
					tt.path, home, got, tt.want)
			}
		})
	}
}

func TestIsSensitiveDeny_caseInsensitive(t *testing.T) {
	const home = `C:\Users\testuser`
	// Same path, different casing — Windows file system is case-insensitive
	// so the classifier must agree.
	cases := []string{
		`C:\Users\TESTUSER\.SSH\id_rsa`,
		`c:\users\testuser\.ssh\id_rsa`,
		`C:\Users\testuser\.Ssh\Id_Rsa`,
	}
	for _, c := range cases {
		if !IsSensitiveDenyAt(c, home) {
			t.Errorf("case-insensitive miss on %q", c)
		}
	}
}

func TestSensitiveRelativePaths_isCopy(t *testing.T) {
	got := SensitiveRelativePaths()
	if len(got) < 11 {
		t.Errorf("expected ≥11 entries, got %d", len(got))
	}
	// Mutate the returned slice — must not affect subsequent calls.
	got[0] = "MUTATED"
	again := SensitiveRelativePaths()
	if again[0] == "MUTATED" {
		t.Errorf("SensitiveRelativePaths returned aliased slice")
	}
}
