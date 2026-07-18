// SPDX-License-Identifier: MIT

package credential

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"
)

// GitIdentity holds the user name and email from the host git config.
type GitIdentity struct {
	Name  string
	Email string
}

// DiscoverGitIdentity reads git user.name and user.email from the global git
// config. Returns a zero-value GitIdentity if git is not installed or not
// configured.
func DiscoverGitIdentity() GitIdentity {
	return GitIdentity{
		Name:  gitConfigValue("user.name"),
		Email: gitConfigValue("user.email"),
	}
}

// ToEnv returns the git identity as a slice of KEY=VALUE strings suitable for
// injection into the sandbox environment.
func (g GitIdentity) ToEnv() []string {
	var env []string
	if g.Name != "" {
		env = append(env, "GIT_AUTHOR_NAME="+g.Name, "GIT_COMMITTER_NAME="+g.Name)
	}
	if g.Email != "" {
		env = append(env, "GIT_AUTHOR_EMAIL="+g.Email, "GIT_COMMITTER_EMAIL="+g.Email)
	}
	return env
}

// gitConfigValue runs `git config --global <key>` and returns the trimmed output.
func gitConfigValue(key string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "git", "config", "--global", key).Output()
	if err != nil {
		return ""
	}
	return Sanitize(strings.TrimSpace(string(bytes.TrimRight(out, "\r\n"))))
}
