// SPDX-License-Identifier: MIT

package credential

import "fmt"

// Credential represents a single host credential to be forwarded into a
// sandboxed session.
type Credential struct {
	// Key is the environment variable name (e.g. "ANTHROPIC_API_KEY").
	Key string
	// Value is the credential value. Treat as a secret — never log.
	Value string
	// Source describes where the credential was discovered (env, gh-cli, etc.).
	Source string
}

// String implements fmt.Stringer with the Value redacted. Any caller
// that accidentally reaches for fmt.Sprintf("%v", cred) — common in
// debug logs — gets the metadata without the secret. Programmatic
// access to Value still works as a regular field.
func (c Credential) String() string {
	if c.Value == "" {
		return fmt.Sprintf("Credential{Key=%s Source=%s Value=}", c.Key, c.Source)
	}
	return fmt.Sprintf("Credential{Key=%s Source=%s Value=[REDACTED]}", c.Key, c.Source)
}

// GoString mirrors String for the %#v format verb. Without this,
// fmt.Sprintf("%#v", cred) would emit the literal struct including
// Value. Belt-and-braces leak prevention.
func (c Credential) GoString() string { return c.String() }

// ToEnv converts the credential to a KEY=VALUE string for os/exec.Cmd.Env.
func (c Credential) ToEnv() string {
	return c.Key + "=" + c.Value
}

// ToEnvSlice converts a slice of credentials to a KEY=VALUE string slice.
func ToEnvSlice(creds []Credential) []string {
	out := make([]string, 0, len(creds))
	for _, c := range creds {
		out = append(out, c.ToEnv())
	}
	return out
}
