// SPDX-License-Identifier: MIT

package config

// DefaultToolchainDeps lists the universal R/W toolchain dependency paths applied to ALL tools.
// These are build-tool home directories (GOPATH, Cargo, pip user installs)
// that AI coding tools spawn as sub-processes — an AI coding tool routinely
// needs to build/test the user's PROJECT in whatever language it's written
// in, regardless of the AI tool's own implementation language, so these stay
// universal rather than gated by the tool's own `runtime:` field. The paths
// are ~ prefixed and filtered by existingPaths() — tools not installed on
// the host are skipped.
//
// Narrower than the full home-relative directory where a meaningfully
// narrower grant covers the same normal-usage functionality:
//   - "~/.local/bin" + "~/.local/lib" (not the whole "~/.local"): pip
//     --user and pipx write only under these two. The full "~/.local" tree
//     also holds "~/.local/share" and "~/.local/state", which on this class
//     of machine commonly hold unrelated apps' data (verified concretely:
//     a version-manager's entire installed-runtime tree lives under
//     "~/.local/share" here) that no coding tool has any legitimate reason
//     to read, let alone write.
var DefaultToolchainDeps = []string{
	"~/go",         // GOPATH: go modules, go install targets, pkg/mod
	"~/.cargo",     // CARGO_HOME: Cargo registry, installed tool binaries
	"~/.local/bin", // pipx-installed scripts, pip --user console_scripts
	"~/.local/lib", // pip --user site-packages
}

// DefaultToolchainDepsRO lists universal R/O toolchain paths — read access
// covers the common case (building/testing an existing project only reads
// an already-installed toolchain); write is a rare, explicit action (e.g.
// `rustup install nightly`) rather than routine build/test activity, so it
// is not granted by default. A profile or `dizgin add-path` can still grant
// RW explicitly for a tool that genuinely needs to manage toolchains itself.
var DefaultToolchainDepsRO = []string{
	"~/.rustup", // RUSTUP_HOME: installed Rust toolchains (read to compile; write only to install/update one)
}

// DefaultToolDeps lists the universal R/W tool dependency paths applied to ALL tools.
// These paths need write access at runtime init — for example, MSYS2 creates /tmp,
// /dev/null, and lock files when bash.exe starts.
// ~/.cache is included for LSP server indexes, MCP tool caches, and build caches
// (gopls, pyright, npm, pip) that tools write during normal operation.
//
// TEMP/TMP/TMPDIR are redirected to a per-session scratch directory via
// buildToolEnv (cmd/dizgin/env.go) so tools that write to %TEMP% hit the session
// scratch path, not the host's user-profile TEMP. The scratch dir is created by
// the restricted backend and cleaned up on session exit.
var DefaultToolDeps = []string{
	"%ProgramFiles%/Git", // MSYS2 runtime: needs /tmp, /dev, lock files at bash init
	"~/.cache",           // LSP indexes, MCP cache, build caches (gopls, pyright, pip, npm)
}

// DefaultMCPDirs lists the universal R/W MCP server directory paths applied to ALL tools.
// MCP (Model Context Protocol) is now universal — all major AI coding tools support it.
// These directories contain MCP server configurations and locally installed server binaries.
//
// Windows note: `%APPDATA%/mcp` used to live here, but on Windows the APPDATA
// env var is overridden by the per-session TEMP redirect (see buildToolEnv),
// so that path no longer resolves predictably and has been removed from the list.
// Tools that want an MCP dir under AppData should add it via profile config_dirs.
var DefaultMCPDirs = []string{
	"~/.mcp", // cross-platform MCP server config and binaries
}

// DefaultEnv holds the universal environment variables applied to ALL tools.
// Profile env keys override these when present; use ExcludeDefaults to remove them.
var DefaultEnv = map[string]string{
	"DO_NOT_TRACK":        "1",                        // universal telemetry opt-out
	"CHOKIDAR_USEPOLLING": "1",                        // file watcher polling for reliability inside the sandbox (inotify/ReadDirectoryChanges events may not fire)
	"WATCHPACK_POLLING":   "true",                     // webpack watcher polling (Node.js bundlers)
	"MSYS":                "winsymlinks:nativestrict", // MSYS2 symlink mode — avoids symlink fallback warnings on init
}

// RuntimeLibDeps returns additional R/O library dependency paths based on the
// tool's runtime field. These are static binary installations that do not need
// write access.
func RuntimeLibDeps(runtime string) []string {
	switch runtime {
	case "nodejs", "node", "electron", "bun":
		return []string{
			"%ProgramFiles%/nodejs",
			"%NODE_HOME%",
			"%APPDATA%/npm", // npm global bin: npx and globally installed MCP server binaries
		}
	case "python":
		return []string{
			"%LOCALAPPDATA%/Programs/Python",
			"%PYTHON_HOME%",
		}
	default:
		return nil
	}
}
