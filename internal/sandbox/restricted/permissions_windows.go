// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/sandbox"
	"github.com/sungurerdim/dizgin/internal/security"
)

// Permission learning persisted state (iter6 Phase D).
//
// One YAML file per tool at ~/.dizgin/permissions/<tool>.yaml. The file
// records the user's last interactive decisions during a `dizgin --learn`
// session: which sensitive paths the tool is allowed to read or write,
// which are denied even if not in the global SSOT, and when the
// decisions were captured.
//
// Auto-load is ON by default: subsequent normal runs read this file and
// pass the overrides into the backend's DENY sweep so the tool gets
// passthrough access to the listed paths without the user having to
// re-run --learn. The user remains in full control via:
//
//   - `dizgin --learn` to re-prompt and overwrite the file.
//   - Direct file edit (the schema is small and human-readable).
//   - Deleting the file to revert to the SSOT default.
//
// Path normalization: stored entries are lowercased + cleaned so the
// case-insensitive Windows filesystem can match consistently regardless
// of how the user typed the path. Environment variables (%USERPROFILE%,
// %APPDATA%, etc.) are expanded on load — storing them unexpanded keeps
// the file portable across machines where the env values differ.
//
// Concurrency: two dizgin sessions for the same tool stamping permissions
// simultaneously would race, but the prompt is human-interactive — the
// realistic race window is the atomic temp+rename write itself, which
// is the standard last-write-wins shape and acceptable for this use.

// permissionsSchemaVersion is the on-disk schema version; bumped only
// when a backwards-incompatible field shape change ships.
const permissionsSchemaVersion = 1

// PermissionProfile is the on-disk record for one tool's learned
// permission overrides. Marshalled to YAML.
type PermissionProfile struct {
	Version   int       `yaml:"version"`
	ToolName  string    `yaml:"tool_name"`
	ToolPath  string    `yaml:"tool_path,omitempty"`
	LearnedAt time.Time `yaml:"learned_at"`
	Overrides Overrides `yaml:"overrides"`
}

// Overrides groups the per-category path lists. Stored values are the
// canonical (lowercased, cleaned, env-expanded) absolute paths so the
// runtime comparison in buildSensitiveDenyJobs is a flat string match.
//
// The schema mirrors sandbox.PermissionOverrides; the two types are
// distinct because Go type aliases cannot carry new struct tags — a
// true alias (type Overrides = sandbox.PermissionOverrides) would
// inherit the tag-free sandbox definition and break YAML marshalling.
// The two converter methods (ToSandboxOverrides / FromSandboxOverrides)
// are the only required boilerplate.
type Overrides struct {
	RW   []string `yaml:"rw,omitempty"`
	RO   []string `yaml:"ro,omitempty"`
	Deny []string `yaml:"deny,omitempty"`
}

// permissionsDir returns ~/.dizgin/permissions, created on first call.
// Returns an error only when USERPROFILE is missing AND home cannot be
// resolved — both extremely rare on a normal Windows host.
func permissionsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("permissions: resolve home: %w", err)
	}
	return filepath.Join(home, brand.DotDir, "permissions"), nil
}

// permissionsPath returns the absolute path to <tool>.yaml. Tool name
// is normalised to lowercase + strip .exe so "Claude.EXE" and "claude"
// resolve to the same file.
//
// IMPORTANT: ToLower MUST run before TrimSuffix because Go's TrimSuffix
// is case-sensitive — TrimSuffix("Claude.EXE", ".exe") returns
// "Claude.EXE" unchanged on a case-mismatched suffix.
func permissionsPath(toolName string) (string, error) {
	dir, err := permissionsDir()
	if err != nil {
		return "", err
	}
	name := strings.TrimSuffix(strings.ToLower(toolName), ".exe")
	if name == "" {
		return "", fmt.Errorf("permissions: empty tool name")
	}
	if err := security.ValidateToolName(name); err != nil {
		return "", err
	}
	return filepath.Join(dir, name+".yaml"), nil
}

// LoadPermissionProfile reads the per-tool YAML if it exists. Returns
// (nil, nil) when the file is missing — a fresh-install / first-run
// state is normal, not an error.
//
// Path entries are env-expanded + normalised on the way out so callers
// (buildSensitiveDenyJobs) can do straight string comparison without
// re-running expand/normalise themselves.
func LoadPermissionProfile(toolName string) (*PermissionProfile, error) {
	path, err := permissionsPath(toolName)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("permissions: read %s: %w", path, err)
	}
	var p PermissionProfile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("permissions: parse %s: %w", path, err)
	}
	p.Overrides = normaliseOverrides(p.Overrides)
	return &p, nil
}

// SavePermissionProfile writes profile atomically (temp file + rename).
// Creates ~/.dizgin/permissions on first use. On Windows, os.Rename uses
// MoveFileEx with MOVEFILE_REPLACE_EXISTING, so the rename atomically
// replaces an existing file in a single filesystem operation.
func SavePermissionProfile(profile *PermissionProfile) error {
	if profile == nil {
		return fmt.Errorf("permissions: nil profile")
	}
	if profile.Version == 0 {
		profile.Version = permissionsSchemaVersion
	}
	if profile.LearnedAt.IsZero() {
		profile.LearnedAt = time.Now().UTC()
	}
	profile.Overrides = normaliseOverrides(profile.Overrides)

	path, err := permissionsPath(profile.ToolName)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("permissions: mkdir %s: %w", dir, err)
	}

	data, err := yaml.Marshal(profile)
	if err != nil {
		return fmt.Errorf("permissions: marshal: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("permissions: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("permissions: rename %s → %s: %w", tmp, path, err)
	}
	return nil
}

// normaliseOverrides expands environment variables and canonicalises
// each path. Empty entries are dropped silently — a corrupted file with
// an empty rw: line should not blow up the next session.
func normaliseOverrides(o Overrides) Overrides {
	return Overrides{
		RW:   canonicalisePaths(o.RW),
		RO:   canonicalisePaths(o.RO),
		Deny: canonicalisePaths(o.Deny),
	}
}

// canonicalisePaths runs each entry through env expansion + Clean +
// ToLower. The lowercase pass matches Windows' case-insensitive
// filesystem semantics; downstream comparators do not need to call
// strings.EqualFold themselves.
//
// Expansion order:
//  1. Trim whitespace; drop empties.
//  2. Tilde rewrite (~/foo, ~\foo, ~) so a hand-edited YAML stays
//     portable across machines that don't honour POSIX-style ~.
//  3. Windows %VAR% expansion (os.ExpandEnv only understands $VAR /
//     ${VAR}, not the Windows shell's percent-delimited form).
//  4. os.ExpandEnv for any remaining POSIX-style references.
//  5. Clean + ToLower to land on the case-insensitive canonical form.
func canonicalisePaths(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		p = expandTilde(p)
		p = expandWindowsEnv(p)
		p = os.ExpandEnv(p)
		if p == "" {
			continue
		}
		out = append(out, strings.ToLower(filepath.Clean(p)))
	}
	return out
}

// expandWindowsEnv rewrites every %VAR% occurrence in p with the
// corresponding os.Getenv value. Unknown variables expand to the
// empty string — same behaviour as cmd.exe — so a typo collapses to
// a clearly-wrong path the canonicaliser then visibly mangles rather
// than silently leaving the literal %VAR% in place.
//
// Iterates left-to-right with manual index tracking instead of a regex
// because the YAML loader only sees small entries (one path per line)
// and the regex compile cost is not amortised over enough calls to
// matter.
func expandWindowsEnv(p string) string {
	for {
		i := strings.Index(p, "%")
		if i < 0 {
			return p
		}
		j := strings.Index(p[i+1:], "%")
		if j < 0 {
			return p
		}
		name := p[i+1 : i+1+j]
		val := os.Getenv(name)
		p = p[:i] + val + p[i+1+j+1:]
	}
}

// expandTilde rewrites a leading ~/ or ~\\ to %USERPROFILE%. Done here
// (not in os.ExpandEnv) because Windows' os.ExpandEnv doesn't honour ~
// the way POSIX shells do; users editing the YAML by hand expect ~/.ssh
// to work regardless of the source platform.
func expandTilde(p string) string {
	if p == "" {
		return p
	}
	if p == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
		return p
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// ToSandboxOverrides projects Overrides into the backend-agnostic
// sandbox.PermissionOverrides shape so backend.Create can route the
// data through opts without leaking yaml-tagged types into the
// sandbox package.
func (o Overrides) ToSandboxOverrides() *sandbox.PermissionOverrides {
	if len(o.RW) == 0 && len(o.RO) == 0 && len(o.Deny) == 0 {
		return nil
	}
	return &sandbox.PermissionOverrides{
		RW:   append([]string{}, o.RW...),
		RO:   append([]string{}, o.RO...),
		Deny: append([]string{}, o.Deny...),
	}
}

// FromSandboxOverrides is the inverse: takes the wire-format overrides
// and packages them into a profile shape ready for SavePermissionProfile.
// The caller still has to fill in ToolName + ToolPath.
func FromSandboxOverrides(o *sandbox.PermissionOverrides) Overrides {
	if o == nil {
		return Overrides{}
	}
	return Overrides{
		RW:   append([]string{}, o.RW...),
		RO:   append([]string{}, o.RO...),
		Deny: append([]string{}, o.Deny...),
	}
}

// isPathExempt reports whether absPath sits under any RW or RO override
// entry (case-insensitive prefix match on Clean()ed forms). Used by
// buildSensitiveDenyJobs to skip stamping a sensitive SSOT path the
// user has already authorised for this tool.
func isPathExempt(absPath string, ov *sandbox.PermissionOverrides) bool {
	if ov == nil {
		return false
	}
	target := strings.ToLower(filepath.Clean(absPath))
	for _, base := range ov.RW {
		if pathMatchesOrUnder(target, base) {
			return true
		}
	}
	for _, base := range ov.RO {
		if pathMatchesOrUnder(target, base) {
			return true
		}
	}
	return false
}

// pathMatchesOrUnder is a separator-boundary prefix check: target equals
// base, or target starts with base + separator. Lowercased forms are
// assumed (Windows case-insensitive); callers pass canonical paths.
func pathMatchesOrUnder(target, base string) bool {
	if target == "" || base == "" {
		return false
	}
	if target == base {
		return true
	}
	sep := string(filepath.Separator)
	return strings.HasPrefix(target, base+sep)
}
