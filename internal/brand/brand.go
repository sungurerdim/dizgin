// SPDX-License-Identifier: MIT

// Package brand is the single source of truth for the product name and
// every runtime identifier derived from it: binary names, environment
// variable prefix, per-user state directory, and daemon IPC endpoints.
//
// Changing the product name is a two-step operation:
//  1. Edit Name (and EnvPrefix, which mirrors it in upper case) below.
//  2. Run `make rename NEW=<name>` for the identifiers Go cannot
//     derive from a constant: the module path, the cmd/ directory
//     names, packaging configs, and documentation prose.
//
// Nothing outside this package may hardcode the brand name in a
// behavior-affecting string (paths, env vars, pipe/socket names,
// binary lookups).
package brand

const (
	// Name is the brand and the sandbox wrapper binary name.
	Name = "dizgin"

	// DaemonName is the orchestration daemon binary name.
	DaemonName = Name + "d"

	// EnvPrefix prefixes every environment variable the binaries read.
	// Kept as an explicit constant because Go const expressions cannot
	// call strings.ToUpper; a test guards that it stays in sync with Name.
	EnvPrefix = "DIZGIN_"

	// DotDir is the per-user state directory name under $HOME
	// (profiles, permissions, deny lists, audit logs, config).
	DotDir = "." + Name

	// PipeName is the Windows named pipe for daemon IPC.
	PipeName = `\\.\pipe\` + DaemonName

	// SocketFile is the unix domain socket file name for daemon IPC.
	SocketFile = DaemonName + ".sock"
)

// Env returns the fully prefixed environment variable name for suffix,
// e.g. Env("NO_WFP") → "DIZGIN_NO_WFP".
func Env(suffix string) string {
	return EnvPrefix + suffix
}

// StateSubdirs are the subdirectories dizgin creates under DotDir on
// every host: per-tool profiles, learned permission overrides, and the
// audit log. SSOT for callers that create, verify, or inventory the
// ~/.dizgin tree (doctor's health check, the zero-config home-dir
// bootstrap, and the verbose preflight dump) so the set can't drift
// between them.
var StateSubdirs = []string{"profiles", "permissions", "audit"}
