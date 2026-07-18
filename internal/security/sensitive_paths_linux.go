// SPDX-License-Identifier: MIT

//go:build linux

package security

import "os"

// sensitiveFoldCase is false on Linux: ext4/btrfs/xfs are case-sensitive,
// so ".ssh" and ".SSH" are genuinely different paths and folding would
// over-match.
const sensitiveFoldCase = false

// sensitiveHome resolves the Linux per-user root.
func sensitiveHome() string { return os.Getenv("HOME") }

// sensitiveRelativePaths is the SSOT list of $HOME-relative credential
// surfaces denied to a sandboxed tool on Linux: the POSIX credential core
// (SSH/PGP, cloud-CLI token caches, k8s/Docker/GitHub/Terraform creds)
// plus the GNOME keyring store and the Chrome/Chromium/Firefox cookie DBs.
//
// Note: bubblewrap enforcement can only cover a sensitive path that falls
// under a declared bind mount (the cover-mount pass); a path that is not
// mounted into the sandbox is already absent (ENOENT) and needs no deny.
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
	".local/share/keyrings",              // GNOME Keyring (login.keyring, etc.)
	".config/google-chrome/Default/Cookies",
	".config/chromium/Default/Cookies",
	".mozilla/firefox",
}
