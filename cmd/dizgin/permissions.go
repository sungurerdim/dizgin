// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/config"
	"github.com/sungurerdim/dizgin/internal/sandbox"
)

// loadPermissionOverrides is the Windows entry point dizgin calls in
// buildSandboxOpts to look up the user's previously-recorded permission
// decisions for this tool. Returns nil on first-run / no-profile /
// load-error paths so the backend falls back to the SSOT default.
//
// backend is type-asserted to sandbox.PermissionProfileLoader; if the
// backend does not implement it (seatbelt / bubblewrap) the call is a
// no-op. This removes the direct cmd/dizgin → internal/sandbox/restricted
// import that previously existed here (ARC-03).
//
// Auto-load is unconditional today; a future opt-out switch could land
// at the YAML config level (e.g. permissions.auto_load: false). The
// expected friction model is: --learn once per tool, never again unless
// the user wants to reconfigure.
func loadPermissionOverrides(toolDef config.ToolDef, toolPath string, backend sandbox.Backend) (string, *sandbox.PermissionOverrides) {
	toolName := derivePermissionToolName(toolDef, toolPath)
	if toolName == "" {
		return "", nil
	}
	loader, ok := backend.(sandbox.PermissionProfileLoader)
	if !ok {
		return toolName, nil
	}
	overrides, err := loader.LoadPermissionOverrides(toolName)
	if err != nil {
		fmt.Fprintf(os.Stderr, brand.Name+": load permissions for %s: %v (falling back to SSOT default)\n",
			toolName, err)
		return toolName, nil
	}
	// Warn on tool-path mismatch: the profile was recorded against a
	// different binary path than the one running now. The overrides still
	// apply, but the user should re-run --learn if this is intentional.
	// We cannot surface the recorded path here without importing the
	// restricted-specific PermissionProfile type, so we omit the per-path
	// warning that the old direct-import version emitted. A future
	// revision can expose a richer interface if the warning proves useful.
	return toolName, overrides
}

// derivePermissionToolName picks the most stable identifier for the
// tool: explicit profile name when present, otherwise the lowercased,
// .exe-stripped basename of the resolved tool path. Returns "" when
// both signals are missing — callers should treat this as "skip
// persistence" rather than fabricating an arbitrary key.
//
// We intentionally do NOT use the user-typed CLI argument because it
// can be a relative path, an alias, or pre-PATH-resolution junk; the
// resolved binary is the only signal that survives a `dizgin -- claude.exe`
// vs `dizgin -- /path/to/claude` invocation.
func derivePermissionToolName(toolDef config.ToolDef, toolPath string) string {
	// ToolDef.Name is not a standardised field on the struct (the
	// registry key is keyed by lowercased basename). Fall straight to
	// the basename derivation — same name the registry uses.
	if toolPath == "" {
		return ""
	}
	base := strings.ToLower(filepath.Base(toolPath))
	base = strings.TrimSuffix(base, ".exe")
	return base
}
