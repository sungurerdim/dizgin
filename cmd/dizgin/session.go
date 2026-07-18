// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/sungurerdim/dizgin/internal/audit"
	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/config"
	"github.com/sungurerdim/dizgin/internal/credential"
	"github.com/sungurerdim/dizgin/internal/log"
	"github.com/sungurerdim/dizgin/internal/platform"
	"github.com/sungurerdim/dizgin/internal/sandbox"
)

// resolveSession resolves workdir, tool path, and loads config.
func resolveSession(toolBin string) (wd, toolPath string, cfg *config.Config, err error) {
	wd, err = resolveWorkdir(workdir)
	if err != nil {
		return
	}
	toolPath, err = lookupTool(toolBin)
	if err != nil {
		fmt.Fprintf(os.Stderr, brand.Name+": command not found: %q (exit %d)\n", toolBin, exitToolNotFound)
		fmt.Fprintf(os.Stderr, "  expected: an executable named %q on your PATH\n", toolBin)
		fmt.Fprintln(os.Stderr, "  fix: install it (e.g. `npm i -g @anthropic-ai/claude-code` for claude), or add its bin dir to PATH.")
		fmt.Fprintf(os.Stderr, "  check: `where %s` (Windows) / `which %s` (Unix) to see what your shell resolves.\n", toolBin, toolBin)
		os.Exit(exitToolNotFound)
	}
	cfg, err = loadConfig(wd)
	if err != nil {
		err = fmt.Errorf("config: %w", err)
	}
	return
}

// initAuditLog configures the audit logger from config/env.
func initAuditLog(cfg *config.Config) {
	if cfg.Audit.Enabled || os.Getenv(brand.Env("AUDIT")) == "true" {
		if err := audit.Configure(true, cfg.Audit.MaxSizeMB); err != nil {
			fmt.Fprintf(os.Stderr, brand.Name+": audit: %v\n", err)
		}
	}
}

// createContext builds a context with optional timeout. The CancelFunc
// is returned to the caller (run() defers it), so the context is not
// leaked.
func createContext(cfg *config.Config) (context.Context, context.CancelFunc) {
	if cfg.Resources.Timeout > 0 {
		return context.WithTimeout(context.Background(), cfg.Resources.Timeout) //nolint:gosec // G118 false positive: cancel is returned to + deferred by the caller
	}
	return context.Background(), func() {}
}

// createSandbox resolves the platform backend and creates a sandbox box.
//
// On Windows: restricted (CreateRestrictedToken + Medium IL + Job +
// per-child mitigation policy bitfield + DACL DENY ACEs on the sensitive
// SSOT).
// On macOS: Seatbelt (sandbox-exec).
// On Linux: bubblewrap (user namespaces + seccomp).
//
// Single backend per platform — there is no broker fallback. If the
// direct create fails, dizgin refuses to run rather than silently degrading
// (see CLAUDE.md no-fallback policy, 2026-05-02).
func createSandbox(ctx context.Context, cfg *config.Config, wd string, toolDef config.ToolDef, toolPath string, creds []sandbox.Credential) (string, sandbox.Box, error) {
	backendName, err := platform.BackendName()
	if err != nil {
		fmt.Fprintf(os.Stderr, brand.Name+": %v\n", err)
		os.Exit(exitBackendUnavailable)
	}

	backend, err := sandbox.Get(backendName)
	if err != nil {
		fmt.Fprintf(os.Stderr, brand.Name+": sandbox backend %q not registered\n", backendName)
		os.Exit(exitBackendUnavailable)
	}
	if !backend.Available() {
		fmt.Fprintln(os.Stderr, brand.Name+": sandbox backend not available.")
		fmt.Fprintln(os.Stderr, "  Windows: restricted backend requires Win 8+ (CreateRestrictedToken + Process Mitigation Policy API).")
		fmt.Fprintln(os.Stderr, "  Linux:   ensure 'bwrap' is on PATH.")
		fmt.Fprintln(os.Stderr, "  macOS:   ensure 'sandbox-exec' is on PATH.")
		os.Exit(exitBackendUnavailable)
	}

	// Wire the stamp-progress callback into the backend now that we have
	// it. applyStampProgress is a no-op on non-Windows (ARC-04).
	applyStampProgress(backend)

	usePTY := !noTTY && isTerminal(os.Stdin) && isTerminal(os.Stdout)
	initialCols, initialRows, _ := currentTerminalSize()
	opts := buildSandboxOpts(wd, toolDef, toolPath, creds, cfg, backend, usePTY, initialCols, initialRows)

	box, createErr := backend.Create(ctx, cfg, opts)
	if createErr != nil {
		return "", nil, fmt.Errorf("create sandbox: %w", createErr)
	}
	return backendName, box, nil
}

// executionContext groups parameters for the sandbox execution phase.
type executionContext struct {
	cfg          *config.Config
	box          sandbox.Box
	toolDef      config.ToolDef
	toolPath     string
	toolBin      string
	toolArgs     []string
	envOverrides []string
	finalCreds   []credential.Credential
	sandboxCreds []sandbox.Credential
	wd           string
	backendName  string
}

// executeTool starts the tool, wires I/O and signals, waits for exit.
//
// Phases: (1) build args/env → (2) start process → (3) zero credentials →
// (4) audit log → (5) daemon + monitor → (6) signal forwarding + I/O →
// (7) wait + teardown.
func executeTool(ctx context.Context, ec *executionContext) error {
	log.Verbose("dizgin:phase", "executeTool start tool=%s backend=%s", ec.toolBin, ec.backendName)

	// Phase 1: Build final args and env.
	toolArgs, toolEnv := buildToolArgsAndEnv(ec)

	// Phase 2: Start the sandboxed process.
	if err := ec.box.Start(ctx, ec.toolPath, toolArgs, toolEnv); err != nil {
		return fmt.Errorf("start tool: %w", err)
	}

	// Phases 3–4b: zero credentials, audit start, network filter.
	sessionID := startSessionLifecycle(ec)

	// Phase 5: Daemon registration + resource monitor.
	daemonClient := registerWithDaemon(ec.toolBin, ec.wd, ec.backendName, ec.box)
	monitorStop := startMonitor(ec.cfg, ec.box, daemonClient)
	defer monitorStop()

	// Phase 6: Signal forwarding + I/O bridge.
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigCh {
			ec.box.Signal(sig) //nolint:errcheck
		}
	}()
	telemetry := runIOBridge(ec)

	// Phase 7: Wait for exit + teardown.
	exitCode, err := ec.box.Wait()
	signal.Stop(sigCh)
	close(sigCh)
	teardownSession(ec, sessionID, exitCode, toolArgs, telemetry, daemonClient)

	if err != nil {
		return fmt.Errorf("wait: %w", err)
	}

	os.Exit(exitCode)
	return nil
}

// buildToolArgsAndEnv constructs the final argument list and environment
// for the sandboxed process (Phase 1).
//
// Args: prepends profile DefaultArgs so user-supplied args can override.
// Env: merges profile env defaults < passthrough < CLI overrides, then
// injects the per-session TEMP redirect (empty on non-Windows backends).
func buildToolArgsAndEnv(ec *executionContext) (args []string, env []string) {
	// Merge profile-defined default_args (e.g., --dangerously-skip-permissions)
	// before user-supplied args so user can still override. Build into a
	// fresh slice — ec.toolDef.DefaultArgs shares its backing array with
	// the profile registry's ToolDef, so appending in place could corrupt
	// it for a concurrent session.
	toolArgs := make([]string, 0, len(ec.toolDef.DefaultArgs)+len(ec.toolArgs))
	toolArgs = append(toolArgs, ec.toolDef.DefaultArgs...)
	toolArgs = append(toolArgs, ec.toolArgs...)

	// Merge default + profile-defined env vars (telemetry disable, perf tweaks)
	// into CLI overrides so they flow into buildToolEnv.
	// Priority (lowest → highest): host env < credentials < default/profile env < passthrough < CLI overrides.
	effectiveEnv := ec.toolDef.EffectiveEnv()
	profileEnvOverrides := make([]string, 0, len(effectiveEnv))
	for k, v := range effectiveEnv {
		profileEnvOverrides = append(profileEnvOverrides, k+"="+v)
	}
	// Passthrough is applied after profile env defaults so host values win.
	passthroughOverrides := buildPassthroughEnv(ec.toolDef.Passthrough)
	allOverrides := append(profileEnvOverrides, passthroughOverrides...)
	allOverrides = append(allOverrides, ec.envOverrides...)

	// Per-session TEMP redirection: tools that self-extract a bundled
	// runtime (Bun SEA — Claude Code's distribution form) must write
	// their $bunfs cache somewhere stable across the spawn. boxTempDir
	// returns the per-session scratch tree allocated in backend.Create.
	// Empty on non-Windows backends today (Seatbelt/bwrap already
	// isolate $TMPDIR); buildToolEnv treats an empty string as opt-out.
	//
	// Profile may force-disable the override via
	//   compatibility:
	//     temp_override: false
	// DIZGIN_NO_TEMP_OVERRIDE=1 still wins as the runtime emergency
	// switch — applied inside buildToolEnv.
	scratchDir := boxTempDir(ec.box)
	compat := ec.toolDef.EffectiveCompatibility()
	if compat.TempOverride != nil && !*compat.TempOverride {
		scratchDir = ""
	}
	return toolArgs, buildToolEnv(ec.finalCreds, allOverrides, scratchDir)
}

// startSessionLifecycle zeros credentials, starts audit logging, and
// applies the network filter (Phases 3–4b). Returns the session ID used
// for audit and network revoke in teardownSession.
func startSessionLifecycle(ec *executionContext) string {
	// Phase 3: Zero credential values from memory.
	credential.ZeroCredentials(ec.finalCreds)
	for i := range ec.sandboxCreds {
		ec.sandboxCreds[i].Value = ""
	}

	// Phase 4: Audit logging.
	sessionID := fmt.Sprintf("%d", os.Getpid())
	for _, c := range ec.finalCreds {
		audit.CredentialInject(sessionID, c.Key, c.Source)
	}
	audit.SessionStart(sessionID, ec.toolBin, ec.wd, ec.backendName)

	// Phase 4b: Network allowlist enforcement. Brokered through the
	// elevated dizgind daemon because dizgin is non-elevated and cannot add
	// WFP filters. Best-effort — failure degrades to advisory and never
	// blocks the tool (network is the accidental-egress interim; R1
	// filesystem is the hard boundary). Revoked in teardownSession.
	applyNetworkFilter(ec.cfg, sessionID, ec.toolPath)
	return sessionID
}

// runIOBridge sets up access telemetry and blocks on the PTY bridge if
// a pseudo-terminal is active (Phase 6 I/O portion). Returns the telemetry
// collector so teardownSession can report denied-path hints after exit.
//
// Signal forwarding goroutine is launched by executeTool before this call
// because the sigCh lifetime spans into Phase 7 and cannot be closed here.
func runIOBridge(ec *executionContext) *accessTelemetry {
	// Access telemetry observes the tool's combined output for "path not
	// found" class errors so the post-exit report can surface paths the
	// user may want to expose via the tool profile. Disabled by setting
	// DIZGIN_NO_ACCESS_TELEMETRY=1.
	var telemetry *accessTelemetry
	if os.Getenv(brand.Env("NO_ACCESS_TELEMETRY")) != "1" {
		telemetry = newAccessTelemetry()
	}

	if pty := ec.box.PTY(); pty != nil {
		var observers []io.Writer
		if telemetry != nil {
			observers = append(observers, telemetry)
		}
		if err := bridgePTY(pty, observers...); err != nil && !isClosedPipeError(err) {
			fmt.Fprintf(os.Stderr, brand.Name+": pty bridge: %v\n", err)
		}
		// PTY disconnected (user closed terminal or tool exited). Signal the
		// container so box.Wait() unblocks instead of hanging indefinitely.
		_ = ec.box.Signal(os.Interrupt)
	}
	return telemetry
}

// deregistrar is the minimal interface teardownSession needs from the
// daemon client. *daemon.Client satisfies it; using the interface here
// keeps session.go free of a daemon import (it lives in monitor.go).
type deregistrar interface {
	Deregister(exitCode int)
}

// teardownSession deregisters the daemon session, revokes the network
// filter, stops audit, cleans up the box, and reports telemetry hints
// (Phase 7 teardown, post-Wait).
func teardownSession(ec *executionContext, sessionID string, exitCode int,
	toolArgs []string, telemetry *accessTelemetry, daemonClient deregistrar,
) {
	// Surface the broker classifier verdict (when present) BEFORE the
	// existing teardown error path. The verdict is a labelled root cause
	// + suggested fix line; printing it before the audit/monitor cleanup
	// keeps it adjacent to the failing tool's last output instead of
	// being buried under exit-time bookkeeping.
	if diag := boxDiagnosis(ec.box); diag != "" {
		fmt.Fprintln(os.Stderr, diag)
	}

	daemonClient.Deregister(exitCode)
	revokeNetworkFilter(ec.cfg, sessionID)
	audit.SessionStop(sessionID, exitCode)

	// Box.Cleanup BEFORE the os.Exit at the end of executeTool so the
	// per-session resources (scratch dir, DACL DENY revoke, Job handle)
	// are released. os.Exit skips deferred cleanup in the caller, so we
	// cannot rely on main.go::run's defer to trigger Box.Cleanup.
	// Cleanup is idempotent — calling it here and again from main.go's
	// defer is safe.
	if cleanErr := ec.box.Cleanup(); cleanErr != nil {
		fmt.Fprintf(os.Stderr, brand.Name+": cleanup: %v\n", cleanErr)
	}

	// Access telemetry: print paths the tool referenced but could not
	// reach. The Report() output includes a `dizgin add-path <path>` hint
	// the user can copy/paste to opt those paths into the tool profile.
	// The 5-way prompt UI was retired in iter4 — too much cognitive
	// load on first run for ambiguous wins; a manual subcommand is
	// less friction once the user knows the path.
	if telemetry != nil {
		// Locale-agnostic fallback: scan the original argv for absolute
		// paths that do not exist on the host. This catches "missing
		// file" errors on every locale, including ones whose stderr
		// regex is not in accessPathPatterns (Turkish, Japanese, …).
		telemetry.NoteFromArgs(toolArgs, exitCode)
		_ = telemetry.Report(os.Stderr)
	}
}

// prepareCredentials discovers host credentials, applies CLI env overrides,
// and returns the merged credential slice plus the sandbox-typed copy.
func prepareCredentials(cfg *config.Config, toolDef config.ToolDef, envOverrides []string) (
	[]credential.Credential, []sandbox.Credential,
) {
	creds, credWarnings := credential.Discover(cfg, toolDef.EnvKeys)
	for _, w := range credWarnings {
		fmt.Fprintln(os.Stderr, w)
	}

	// Merge env overrides on top of discovered credentials.
	credsMap := make(map[string]credential.Credential, len(creds))
	for _, c := range creds {
		credsMap[c.Key] = c
	}
	for _, kv := range envOverrides {
		k, v := credential.SplitKV(kv)
		credsMap[k] = credential.Credential{Key: k, Value: v, Source: "cli"}
	}
	finalCreds := make([]credential.Credential, 0, len(credsMap))
	for _, c := range credsMap {
		finalCreds = append(finalCreds, c)
	}

	sandboxCreds := make([]sandbox.Credential, 0, len(finalCreds))
	for _, c := range finalCreds {
		sandboxCreds = append(sandboxCreds, sandbox.Credential{Key: c.Key, Value: c.Value})
	}
	return finalCreds, sandboxCreds
}

// boxDiagnosis returns the broker's classifier verdict for a brokered
// box, or "" for any other box type. Type-assertion on a tiny
// interface keeps session.go free of platform-specific imports — the
// brokerBox lives in broker_box_{windows,other}.go and exposes
// LastDiagnosis through this contract.
func boxDiagnosis(b sandbox.Box) string {
	d, ok := b.(interface{ LastDiagnosis() string })
	if !ok {
		return ""
	}
	return d.LastDiagnosis()
}

// boxTempDir returns the per-session scratch directory exposed by the
// restricted backend (or "" when the box has no per-session scratch,
// e.g. Seatbelt/bwrap where $TMPDIR is already isolated by the
// platform sandbox primitive). The tiny single-method assertion keeps
// session.go free of platform-specific imports — only the Windows
// box.TempDir() string return is consulted here.
func boxTempDir(b sandbox.Box) string {
	d, ok := b.(interface{ TempDir() string })
	if !ok {
		return ""
	}
	return d.TempDir()
}

// buildSandboxOpts constructs the CreateOpts for the given session parameters.
// backend is the already-resolved Backend (passed so permission overrides can
// be loaded via the PermissionProfileLoader optional interface without
// requiring a concrete backend import in cmd/dizgin).
func buildSandboxOpts(wd string, toolDef config.ToolDef, toolPath string,
	sandboxCreds []sandbox.Credential, cfg *config.Config, backend sandbox.Backend, usePTY bool,
	initialCols, initialRows uint16,
) sandbox.CreateOpts {
	compat := toolDef.EffectiveCompatibility()
	// Permission learning: look up persisted overrides for this tool.
	// On Windows, routes through the PermissionProfileLoader optional
	// interface so cmd/dizgin never imports the concrete backend package.
	// On non-Windows, loadPermissionOverrides is a compile-time no-op.
	toolName, permOverrides := loadPermissionOverrides(toolDef, toolPath, backend)
	return sandbox.CreateOpts{
		Workdir:     wd,
		Mounts:      buildMounts(wd, toolDef, toolPath),
		Credentials: sandboxCreds,
		Network:     cfg.Network.Policy,
		Allowlist:   cfg.Network.Allowlist,
		Resources: sandbox.ResourceLimits{
			MemoryMB:   cfg.Resources.MemoryMB,
			CPUPercent: cfg.Resources.CPUPercent,
			MaxPIDs:    cfg.Resources.MaxPIDs,
			Timeout:    cfg.Resources.Timeout,
		},
		PTY:                 usePTY,
		InitialCols:         initialCols,
		InitialRows:         initialRows,
		HandleListAllowlist: compat.HandleListAllowlist,
		LearnMode:           learnMode,
		BlockNonMicrosoftBinaries: func() *bool {
			if compat.MitigationPolicy == nil {
				return nil
			}
			return compat.MitigationPolicy.BlockNonMicrosoftBinaries
		}(),
		PermissionOverrides: permOverrides,
		ToolName:            toolName,
		ToolPath:            toolPath,
	}
}
