// SPDX-License-Identifier: MIT

package config

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ConfigDirEntry is the structured form of a single config_dirs entry.
// Profiles accept two shapes (see UnmarshalYAML):
//
//	config_dirs:
//	  - "~/.claude.json"               # legacy bare string (Mode=rw, Source=profile)
//	  - path: "~/.local/share/pnpm"    # structured
//	    mode: rw
//	    source: auto
//	    added: "2026-04-22T10:30:00Z"
//
// Storing Mode, Source and Added lets the dynamic access learning loop
// decide later whether to keep the entry, upgrade it, or report it back
// to the user — without destroying the distinction between profile-
// declared and user-auto-accepted paths.
type ConfigDirEntry struct {
	Path   string    `yaml:"path"`
	Mode   string    `yaml:"mode,omitempty"`   // "rw" (default) | "ro"
	Source string    `yaml:"source,omitempty"` // "profile" (default) | "auto" | "manual"
	Added  time.Time `yaml:"added,omitempty"`
}

// ConfigDirMode returns the mount mode, normalising unknown values to "rw".
func (e ConfigDirEntry) ConfigDirMode() string {
	switch strings.ToLower(strings.TrimSpace(e.Mode)) {
	case "ro", "readonly", "read-only":
		return "ro"
	default:
		return "rw"
	}
}

// ReadOnly is a convenience predicate — true iff the entry should be mounted RO.
func (e ConfigDirEntry) ReadOnly() bool { return e.ConfigDirMode() == "ro" }

// ConfigDirList is the YAML-facing wrapper that accepts both the bare-string
// legacy form and the structured form in a single list. It exists so the
// profile loader can ingest either shape without duplicate code paths.
type ConfigDirList []ConfigDirEntry

// UnmarshalYAML accepts a sequence whose elements are either scalar strings
// or mappings. Scalars are promoted to structured entries with Mode="rw"
// and Source="profile" — matching the behaviour profiles had before the
// v2 refactor.
func (c *ConfigDirList) UnmarshalYAML(value *yaml.Node) error {
	if value == nil || value.Kind != yaml.SequenceNode {
		return nil
	}
	out := make(ConfigDirList, 0, len(value.Content))
	for _, n := range value.Content {
		switch n.Kind {
		case yaml.ScalarNode:
			out = append(out, ConfigDirEntry{
				Path:   n.Value,
				Mode:   "rw",
				Source: "profile",
			})
		case yaml.MappingNode:
			var e ConfigDirEntry
			if err := n.Decode(&e); err != nil {
				return fmt.Errorf("config_dirs entry: %w", err)
			}
			if e.Path == "" {
				return fmt.Errorf("config_dirs entry missing path")
			}
			if e.Mode == "" {
				e.Mode = "rw"
			}
			if e.Source == "" {
				e.Source = "profile"
			}
			out = append(out, e)
		default:
			return fmt.Errorf("config_dirs entry: unsupported YAML kind %d", n.Kind)
		}
	}
	*c = out
	return nil
}

// Paths returns only the bare path strings — used for the legacy
// []string ConfigDirs field on ToolDef so existing callers keep working.
func (c ConfigDirList) Paths() []string {
	if len(c) == 0 {
		return nil
	}
	out := make([]string, 0, len(c))
	for _, e := range c {
		out = append(out, e.Path)
	}
	return out
}
