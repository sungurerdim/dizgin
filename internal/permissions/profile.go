// SPDX-License-Identifier: MIT

// Package permissions reads the per-tool permission overrides that dizgin
// persists at ~/.dizgin/permissions/<tool>.yaml. It is the cross-platform
// loader used by the POSIX backends (seatbelt, bubblewrap) so a user can
// authorise a sensitive path for a tool by editing that YAML — the same
// file the Windows --learn flow writes.
//
// The Windows restricted backend has its own richer copy of this schema
// wired into its DACL sweep; this package deliberately does not touch it.
// A future consolidation can merge the two behind this package.
package permissions

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/sandbox"
	"github.com/sungurerdim/dizgin/internal/security"
)

// profileFile is the on-disk YAML shape. Only the fields the loader needs
// are modelled; unknown fields are ignored by the decoder.
type profileFile struct {
	Version   int       `yaml:"version"`
	ToolName  string    `yaml:"tool_name"`
	Overrides overrides `yaml:"overrides"`
}

type overrides struct {
	RW   []string `yaml:"rw,omitempty"`
	RO   []string `yaml:"ro,omitempty"`
	Deny []string `yaml:"deny,omitempty"`
}

// Dir returns ~/.dizgin/permissions. It does not create the directory —
// the POSIX side only reads; the Windows --learn flow owns writes.
func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("permissions: resolve home: %w", err)
	}
	return filepath.Join(home, brand.DotDir, "permissions"), nil
}

// path returns the absolute path to <tool>.yaml. The tool name is
// normalised to lowercase so "Claude" and "claude" resolve to one file.
func path(toolName string) (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	name := strings.ToLower(strings.TrimSpace(toolName))
	if name == "" {
		return "", fmt.Errorf("permissions: empty tool name")
	}
	if err := security.ValidateToolName(name); err != nil {
		return "", err
	}
	return filepath.Join(dir, name+".yaml"), nil
}

// Load reads the per-tool overrides and returns them in the backend-agnostic
// sandbox shape, or (nil, nil) when no profile exists yet (a normal
// first-run state, not an error). Paths are canonicalised (tilde + env
// expansion + Clean) so backends can compare them directly.
func Load(toolName string) (*sandbox.PermissionOverrides, error) {
	p, err := path(toolName)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("permissions: read %s: %w", p, err)
	}
	var pf profileFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("permissions: parse %s: %w", p, err)
	}
	ov := &sandbox.PermissionOverrides{
		RW:   canonicalise(pf.Overrides.RW),
		RO:   canonicalise(pf.Overrides.RO),
		Deny: canonicalise(pf.Overrides.Deny),
	}
	if len(ov.RW) == 0 && len(ov.RO) == 0 && len(ov.Deny) == 0 {
		return nil, nil
	}
	return ov, nil
}

// canonicalise expands ~ and environment variables in each entry, cleans
// the result, and drops empties. POSIX semantics ($VAR / ${VAR}); the
// case is preserved because Linux is case-sensitive (macOS callers already
// resolve their own folding at match time).
func canonicalise(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		p = expandTilde(p)
		p = os.ExpandEnv(p)
		if p == "" {
			continue
		}
		out = append(out, filepath.Clean(p))
	}
	return out
}

// expandTilde rewrites a leading ~ or ~/ to the user's home directory so a
// hand-edited YAML can use the portable ~/.ssh form.
func expandTilde(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if p == "~" {
				return home
			}
			return filepath.Join(home, p[2:])
		}
	}
	return p
}
