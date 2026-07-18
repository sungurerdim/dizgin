// SPDX-License-Identifier: MIT

package credential

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"time"
)

// DiscoverGitHubToken attempts to resolve a GitHub personal access token from
// multiple sources, in priority order:
//  1. GITHUB_TOKEN environment variable
//  2. GH_TOKEN environment variable (gh CLI convention)
//  3. `gh auth token` (gh CLI)
//  4. `git credential fill` for github.com
//
// Returns an empty string if no token is found.
func DiscoverGitHubToken() string {
	// 1. GITHUB_TOKEN env var.
	if tok := Sanitize(os.Getenv("GITHUB_TOKEN")); tok != "" {
		return tok
	}
	// 2. GH_TOKEN env var.
	if tok := Sanitize(os.Getenv("GH_TOKEN")); tok != "" {
		return tok
	}
	// 3. gh CLI.
	if tok := ghAuthToken(); tok != "" {
		return tok
	}
	// 4. git credential helper.
	if tok := gitCredentialToken(); tok != "" {
		return tok
	}
	return ""
}

// ghAuthToken calls `gh auth token` and returns the trimmed output.
func ghAuthToken() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "gh", "auth", "token").Output()
	if err != nil {
		return ""
	}
	return Sanitize(strings.TrimSpace(string(out)))
}

// gitCredentialToken tries to obtain a GitHub token via `git credential fill`.
func gitCredentialToken() string {
	input := "protocol=https\nhost=github.com\n\n"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "credential", "fill")
	cmd.Stdin = bytes.NewBufferString(input)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "password=") {
			return Sanitize(strings.TrimPrefix(line, "password="))
		}
	}
	return ""
}
