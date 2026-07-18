// SPDX-License-Identifier: MIT

// Package sandbox defines the Backend and Box interfaces implemented by
// each platform-specific sandbox backend (restricted, Seatbelt, bubblewrap).
package sandbox

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/sungurerdim/dizgin/internal/config"
)

// Backend is a factory for creating sandboxed execution environments.
// Each platform (Windows/macOS/Linux) registers exactly one Backend.
type Backend interface {
	// Name returns the unique backend identifier (e.g. "restricted", "seatbelt", "bubblewrap").
	Name() string
	// Available reports whether the backend can run on the current host.
	Available() bool
	// Create configures a new Box ready to start a sandboxed process.
	// ctx controls the lifetime of the resulting Box.
	Create(ctx context.Context, cfg *config.Config, opts CreateOpts) (Box, error)
}

// Box is a single sandboxed execution environment.
// It is created by Backend.Create and used by the dizgin wrapper.
type Box interface {
	// Start launches the sandboxed process. cmd is the tool binary path;
	// args are the tool arguments; env is the environment to inject.
	// ctx cancellation terminates the sandboxed process.
	Start(ctx context.Context, cmd string, args []string, env []string) error
	// Wait blocks until the sandboxed process exits and returns its exit code.
	Wait() (int, error)
	// Signal forwards an OS signal to the sandboxed process.
	Signal(sig os.Signal) error
	// PTY returns the pseudo-terminal connected to the sandboxed process,
	// or nil if PTY mode is not active.
	PTY() io.ReadWriteCloser
	// Pid returns the sandboxed process ID, or 0 if not started.
	Pid() int
	// Cleanup releases all resources held by the Box (mounts, temp files,
	// cgroup handles, etc.). Must be called after Wait returns.
	Cleanup() error
}

// CreateOpts carries per-session creation options passed from the wrapper to the backend.
type CreateOpts struct {
	// Workdir is the working directory for the sandboxed process.
	Workdir string
	// Mounts is the list of filesystem mount directives derived from the config.
	Mounts []Mount
	// Credentials holds forwarded host credentials for the session.
	Credentials []Credential
	// Network describes the network policy to enforce.
	Network config.NetworkPolicy
	// Allowlist is the list of allowed hosts when Network == config.NetworkAllowlist.
	Allowlist []string
	// Resources limits CPU, memory, and PID count.
	Resources ResourceLimits
	// PTY enables pseudo-terminal allocation.
	PTY bool
	// InitialCols and InitialRows set the ConPTY initial dimensions so the
	// container process starts at the correct terminal size instead of defaulting
	// to 80×24. Set these to the current host terminal size before calling Create.
	InitialCols uint16
	InitialRows uint16

	// HandleListAllowlist (iter5 Layer 2 + Layer 4) controls whether
	// the backend appends a PROC_THREAD_ATTRIBUTE_HANDLE_LIST entry to
	// its PTAL so only the three stdio handles inherit into the child.
	// nil → use backend default (currently ON). false → disable the
	// allowlist entry; legacy behaviour where every inheritable handle
	// in dizgin's table reaches the child. Wired from the tool profile's
	// `compatibility.handle_list_allowlist:` YAML field.
	HandleListAllowlist *bool

	// LearnMode is the iter6 Phase 5 permission-learning toggle. When
	// true, the backend keeps the sensitive DENY stamps in place but
	// wraps the child's stderr with an access-denial recorder. On
	// session exit, dizgin prints a summary of the captured denial lines
	// so the user can decide which sensitive surfaces (if any) to
	// allow on the next run. Wired from dizgin's `--learn` flag.
	LearnMode bool

	// BlockNonMicrosoftBinaries (iter6 Phase C) controls whether the
	// restricted backend sets the PROCESS_CREATION_MITIGATION_POLICY_
	// BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON bit when spawning the
	// child. nil → use the backend's compiled default (currently OFF
	// because the mitigation blocks every third-party DLL load). When
	// non-nil, the backend overrides Policies.BlockNonMicrosoftBinaries
	// with the dereferenced value. Wired from the tool profile's
	// `compatibility.mitigation_policy.block_non_microsoft_binaries:`
	// YAML field.
	BlockNonMicrosoftBinaries *bool

	// PermissionOverrides (iter6 Phase D) carries per-tool exceptions
	// the user authorised on a previous --learn run. The restricted
	// backend consults this when computing its DENY sweep: paths listed
	// in RW or RO are skipped (the user opted them out of the
	// session-scoped DENY), paths in Deny are stamped even if not in
	// the SSOT (user wants extra coverage for this tool).
	//
	// nil → no overrides loaded (first run, or no profile for this
	// tool, or running on a platform whose backend doesn't honour the
	// overrides yet). Backends ignore unknown fields gracefully.
	PermissionOverrides *PermissionOverrides

	// ToolName (iter6 Phase D) is the normalised tool identifier used
	// to key into ~/.dizgin/permissions/<tool>.yaml. Lowercased, .exe
	// suffix stripped — matches the keys dizgin's profile registry uses.
	// Empty when dizgin could not derive a stable name; the backend's
	// learn-mode persistence falls back to skipping the save in that
	// case rather than writing to an unidentified file.
	ToolName string

	// ToolPath (iter6 Phase D) is the absolute path of the resolved
	// tool binary at the time the session started. Recorded into the
	// permission profile so a future run can warn when the tool has
	// moved (e.g. after a reinstall), prompting the user to re-confirm
	// the saved decisions.
	ToolPath string
}

// PermissionOverrides is the backend-agnostic view of a per-tool
// permission profile (~/.dizgin/permissions/<tool>.yaml). It carries
// only absolute paths so backends can apply them without re-parsing
// YAML or re-expanding environment variables.
//
// The restricted backend treats RW and RO identically today (both
// skip the DENY stamp on the listed path); the slot distinction is
// preserved for future tightening where RO could keep a read-only
// shim instead of full passthrough.
type PermissionOverrides struct {
	// RW: paths the tool may read AND write. Excluded from the
	// sensitive DENY sweep.
	RW []string
	// RO: paths the tool may read. Excluded from the sensitive DENY
	// sweep (backend may apply a read-only shim in a future revision).
	RO []string
	// Deny: paths the user wants explicitly DENY'd for this tool even
	// when they are not in the global sensitive SSOT (e.g. project
	// secrets the tool should never touch). Stamped in addition to
	// the SSOT set.
	Deny []string
}

// MountCategory tags a Mount with its place in the iter4 3-tier R
// model. The restricted backend (Windows) and the Seatbelt / bwrap
// mirrors (macOS / Linux) use the category for audit-log clarity and,
// where relevant, to decide whether a path needs extra handling.
//
// On the iter6 restricted backend the category is no longer used to
// drive per-path stamping (the DENY-list model in
// internal/security/sensitive_paths_windows.go applies a fixed SSOT
// instead of an allowlist), but the tag is retained because the audit
// log + mount classifier in cmd/dizgin/mounts.go still emit it and the
// Seatbelt / bwrap backends use it directly for their RO/RW decisions.
type MountCategory string

const (
	// CategoryWorkdir is R1-A — the per-session project workdir. Always
	// RW. Stamp failure aborts session creation.
	CategoryWorkdir MountCategory = "workdir"
	// CategoryDeclaredRW is R1-B — profile-declared read-write paths
	// (config_dirs, mcp_dirs, tool_deps read_write entries, npm cache).
	CategoryDeclaredRW MountCategory = "declared_rw"
	// CategoryDeclaredRO is R1-C — profile-declared read-only paths
	// (tool_deps read_only, lib_deps). On Seatbelt / bwrap the
	// classifier maps this to a read-only bind; on restricted the
	// user's natural NTFS permissions provide RO unless a DENY ACE
	// from the sensitive SSOT covers the path.
	CategoryDeclaredRO MountCategory = "declared_ro"
	// CategoryPath is host PATH entries the user inherited. On
	// restricted, covered by the user's own NTFS ACEs; tagged
	// separately for audit-log clarity.
	CategoryPath MountCategory = "path"
	// CategorySystem is OS-managed directories (Windows, Program Files,
	// ProgramData). RO under the user's natural NTFS rights; the
	// classifier never needs to alter ACLs on these.
	CategorySystem MountCategory = "system"
)

// Rank returns the strength of c for dedup merges: when two mounts
// resolve to the same host path under different categories, the
// classifier keeps the strongest one so a path declared RW for the
// workdir never gets demoted to RO via a PATH-entry overlap.
func (c MountCategory) Rank() int {
	switch c {
	case CategoryWorkdir:
		return 5
	case CategoryDeclaredRW:
		return 4
	case CategoryDeclaredRO:
		return 3
	case CategoryPath:
		return 2
	case CategorySystem:
		return 1
	}
	return 0
}

// Mount describes a single filesystem bind-mount inside the sandbox.
type Mount struct {
	// Host is the absolute path on the host.
	Host string
	// Guest is the absolute path inside the sandbox.
	Guest string
	// ReadOnly marks the mount as read-only.
	ReadOnly bool
	// Category positions the mount in the 3-tier R model so the backend
	// classifier (restricted.Create on Windows; seatbelt / bwrap on
	// macOS / Linux) can route it correctly. Empty when older callers
	// construct Mount values without category data — the classifier
	// falls back to inferring from ReadOnly + path shape.
	Category MountCategory
}

// Credential is a forwarded host credential injected into the sandbox environment.
type Credential struct {
	// Key is the environment variable name (e.g. "ANTHROPIC_API_KEY").
	Key string
	// Value is the credential value. Treat as a secret; do not log.
	Value string
}

// PermissionProfileLoader is an optional interface a Backend may implement
// to expose per-tool learned permission overrides without requiring callers
// to import a concrete backend package. cmd/dizgin type-asserts the registered
// backend to this interface; backends that do not implement it return
// (nil, nil) gracefully via the type-assertion zero value.
//
// Wired by the Windows restricted backend only; seatbelt / bubblewrap do
// not implement it (permissions are modelled per-mount at Create time).
type PermissionProfileLoader interface {
	// LoadPermissionOverrides returns the sandbox-typed overrides for
	// toolName, or (nil, nil) when no profile has been saved yet.
	LoadPermissionOverrides(toolName string) (*PermissionOverrides, error)
}

// StampProgressSetter is an optional interface a Backend may implement to
// register a progress callback for DACL-stamp operations. cmd/dizgin
// type-asserts the backend after registry lookup and calls SetStampProgress
// when a renderer is available (TTY stderr). Backends that do not stamp
// (seatbelt / bubblewrap) simply do not implement this interface.
type StampProgressSetter interface {
	// SetStampProgress wires cb as the stamp-progress reporter.
	// Passing nil clears a previously registered callback.
	SetStampProgress(cb func(done, total int))
}

// SelfTestResult is the outcome of a Backend's SelfTest probe.
type SelfTestResult struct {
	// OK reports whether the probe succeeded.
	OK bool
	// Summary is a one-line human-readable description: what was
	// checked and its outcome (success or failure detail).
	Summary string
	// Hint is a remediation suggestion, populated only when !OK.
	Hint string
}

// SelfTester is an optional interface a Backend may implement to expose a
// lightweight startup-primitive smoke test for `dizgin doctor`, without
// requiring doctor to import the concrete backend package. Backends with
// nothing worth probing beyond Available() do not implement it.
type SelfTester interface {
	// SelfTest exercises the backend's core primitive (e.g. restricted
	// token creation on Windows) and reports the outcome.
	SelfTest() SelfTestResult
}

// ResourceLimits caps resource usage inside the sandbox.
type ResourceLimits struct {
	// MemoryMB is the resident memory cap in mebibytes (0 = unlimited).
	MemoryMB int
	// CPUPercent is the CPU share cap (0-100, 0 = unlimited).
	CPUPercent int
	// MaxPIDs is the maximum number of processes (0 = unlimited).
	MaxPIDs int
	// Timeout terminates the session after the given duration (0 = no limit).
	Timeout time.Duration
}
