// SPDX-License-Identifier: MIT

//go:build windows

package security

import "os"

// sensitiveFoldCase is true on Windows: NTFS is case-insensitive, so a
// ".SSH" spelling must still match the ".ssh" rule.
const sensitiveFoldCase = true

// sensitiveHome resolves the Windows per-user root.
func sensitiveHome() string { return os.Getenv("USERPROFILE") }

// sensitiveRelativePaths is the SSOT list of %USERPROFILE%-relative paths
// that receive a DACL DENY ACE on every restricted-backend session.
//
// Includes the Windows DPAPI credential surface: CryptoAPI RSA/DSS keys
// under AppData\Roaming\Microsoft\Crypto AND the DPAPI master keys +
// CREDHIST under AppData\Roaming\Microsoft\Protect (distinct directories,
// both needed to lock down credential decryption), the Credential Manager
// and Vault stores, and browser cookie DBs.
//
// Trade-off: a DACL DENY on the user SID also blocks the user's *other*
// processes (ssh-agent, a git push from another terminal) for the
// duration of the session. Accepted for the restricted-backend MVP; the
// Cleanup path always revokes and the audit log records every applied
// DENY so an orphan sweeper can recover if dizgin crashes mid-session.
var sensitiveRelativePaths = []string{
	`.ssh`,
	`.aws\credentials`,
	`.aws\config`,
	`.gnupg`,
	`.netrc`,
	`.docker\config.json`,
	`.kube`,
	`.git-credentials`,
	`.config\gh\hosts.yml`,
	`.azure`,                             // Azure CLI token cache (msal_token_cache.json) + service principal creds
	`.config\gcloud`,                     // GCP application-default credentials + access_tokens.db
	`.terraform.d\credentials.tfrc.json`, // Terraform Cloud / Enterprise API token
	`AppData\Roaming\Microsoft\Crypto`,   // CryptoAPI RSA / DSS private keys (per-user)
	`AppData\Roaming\Microsoft\Protect`,  // DPAPI master keys (<SID>\) + CREDHIST
	`AppData\Local\Microsoft\Credentials`,
	`AppData\Local\Microsoft\Vault`,
	`AppData\Local\Google\Chrome\User Data\Default\Cookies`,
	`AppData\Local\Microsoft\Edge\User Data\Default\Cookies`,
	`AppData\Roaming\Mozilla\Firefox\Profiles`,
}
