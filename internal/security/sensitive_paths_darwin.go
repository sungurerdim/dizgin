// SPDX-License-Identifier: MIT

//go:build darwin

package security

import "os"

// sensitiveFoldCase is true on macOS: the default APFS volume is
// case-insensitive, so a ".SSH" spelling must still match ".ssh".
// (A case-sensitive APFS volume is rarer and folding there only ever
// over-matches within the user's own home, which is the safe direction.)
const sensitiveFoldCase = true

// sensitiveHome resolves the macOS per-user root.
func sensitiveHome() string { return os.Getenv("HOME") }

// sensitiveRelativePaths is the SSOT list of $HOME-relative credential
// surfaces denied to a sandboxed tool on macOS: the POSIX credential core
// (SSH/PGP, cloud-CLI token caches, k8s/Docker/GitHub/Terraform creds)
// plus the macOS-specific login/keychain store and the browser cookie DBs
// under ~/Library/Application Support.
var sensitiveRelativePaths = []string{
	".ssh",
	".aws/credentials",
	".aws/config",
	".gnupg",
	".netrc",
	".docker/config.json",
	".kube",
	".git-credentials",
	".config/gh/hosts.yml",
	".azure",                             // Azure CLI token cache + service principal creds
	".config/gcloud",                     // GCP application-default credentials + access_tokens.db
	".terraform.d/credentials.tfrc.json", // Terraform Cloud / Enterprise API token
	"Library/Keychains",                  // login.keychain-db + other user keychains
	"Library/Application Support/Google/Chrome/Default/Cookies",
	"Library/Application Support/Microsoft Edge/Default/Cookies",
	"Library/Application Support/Firefox/Profiles",
}
