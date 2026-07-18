// SPDX-License-Identifier: MIT

//go:build windows

// Package restricted implements a Windows sandbox backend built on
// CreateRestrictedToken (DISABLE_MAX_PRIVILEGE) + Medium Integrity +
// Job Object + per-child Process Mitigation Policies + DACL DENY ACEs
// on sensitive paths. It is the iter6 replacement for the AppContainer
// backend, motivated by CLAUDE-HANG-01: Bun SEA binaries (Claude Code's
// runtime) wedge under AppContainer because Bun's in-process JIT
// collides with the ACG mitigation AppContainer auto-applies. The
// iter6 model keeps ACG OFF by default (see mitigation_windows.go)
// so JIT runtimes load cleanly, and recovers blast-radius reduction
// via privilege drop + IL drop + Job + targeted DACL DENY rather
// than capability isolation.
//
// The trade-off vs the retired AppContainer path is documented in
// docs/SECURITY.md: R7 (kernel boundary) drops from
// `kernel-shared/capability-restricted` to `kernel-shared/restricted-
// token`. R1 (FS isolation) is preserved but enforced via DENY ACEs
// on a hardcoded sensitive-path list (acl_windows.go) plus implicit
// DENY on `C:\Users\<other>\*`. R2 (native experience) is preserved
// unchanged — `host_path == guest_path`, no translation.
//
// Requirements:
//   - Windows 8 or newer (Process Mitigation Policy API).
//   - advapi32.dll, kernel32.dll (every supported Windows ships these).
//   - No admin / UAC elevation. The backend is intentionally usable
//     from a normal dizgin process.
package restricted

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/sungurerdim/dizgin/internal/audit"
	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/config"
	"github.com/sungurerdim/dizgin/internal/log"
	"github.com/sungurerdim/dizgin/internal/sandbox"
	"github.com/sungurerdim/dizgin/internal/security"
)

func init() {
	sandbox.Register(&backend{})
	// Wire RevokePathForTrustee into internal/security so cmd/dizgind heal
	// can call it without importing this package directly (ARC-05). The
	// implementation stays here (restricted owns the DACL stamping
	// machinery); security owns the public seam.
	security.RevokePathForTrustee = RevokePathForTrustee
}

type backend struct{}

func (b *backend) Name() string { return sandbox.BackendNameRestricted }

// Available reports whether the backend can run on the current host.
//
// We probe the three syscalls the box spawn path needs: the restricted-
// token constructor, the mitigation getter (proxy for Process Mitigation
// Policy API surface), and the PTAL updater (Job + handle list + child
// mitigation are all routed through it). Win8+ ships all three; the
// probe protects against unusual custom images that strip exports.
func (b *backend) Available() bool {
	if err := procCreateRestrictedToken.Find(); err != nil {
		log.Debug("restricted: CreateRestrictedToken not exported: %v", err)
		return false
	}
	if err := procGetProcessMitigationPolicy.Find(); err != nil {
		log.Debug("restricted: GetProcessMitigationPolicy not exported: %v", err)
		return false
	}
	if err := procUpdateProcThreadAttribute.Find(); err != nil {
		log.Debug("restricted: UpdateProcThreadAttribute not exported: %v", err)
		return false
	}
	return true
}

// Create configures a fresh restricted Box: resolves the user SID,
// applies the sensitive-path DENY ACE sweep, allocates a per-session
// scratch dir, and returns a Box ready for Start().
//
// The DENY sweep runs in parallel and is idempotent: paths that don't
// exist are skipped (a sensitive file created mid-session does not
// retroactively get a DENY — accepted MVP trade-off). Failure on a
// single sensitive path aborts session creation under R1 fail-closed:
// a partial DENY is worse than no DENY because the user expects the
// session-scoped credential isolation to hold.
func (b *backend) Create(ctx context.Context, cfg *config.Config, opts sandbox.CreateOpts) (sandbox.Box, error) {
	t0 := time.Now()
	mark := func(name string) {
		if log.IsTimingEnabled() {
			fmt.Fprintf(os.Stderr, brand.Name+": restricted.Create.%s elapsed %.2fs\n",
				name, time.Since(t0).Seconds())
		}
	}

	userSID, err := CurrentUserSID()
	if err != nil {
		return nil, fmt.Errorf("restricted: resolve user SID: %w", err)
	}
	mark("userSID")

	sessionID := fmt.Sprintf(brand.Name+"-%d-%d", os.Getpid(), time.Now().UnixNano())
	scratchDir, err := SessionScratchDir(sessionID)
	if err != nil {
		return nil, fmt.Errorf("restricted: scratch dir: %w", err)
	}
	mark("scratchDir")

	denied, err := stampPaths(sessionID, scratchDir, opts.PermissionOverrides, userSID, mark)
	if err != nil {
		return nil, err
	}

	return buildBox(ctx, opts, sessionID, scratchDir, userSID, denied), nil
}

// stampPaths runs the sensitive-path DENY ACE sweep and returns the list
// of successfully-stamped paths. On first error it rolls back all partial
// stamps, removes scratchDir, and returns a descriptive error (R1
// fail-closed). mark is the optional timing callback from Create.
func stampPaths(
	sessionID, scratchDir string,
	overrides *sandbox.PermissionOverrides,
	userSID *windows.SID,
	mark func(string),
) (denied []string, err error) {
	userProfile := os.Getenv("USERPROFILE")
	if userProfile == "" {
		log.DebugSub(log.SubContainer, "restricted: USERPROFILE empty, skipping DENY sweep")
	}
	jobs := buildSensitiveDenyJobs(sessionID, userProfile, overrides)
	mark("denyJobs")

	if len(jobs) == 0 {
		return nil, nil
	}

	completed, firstErrPath, firstErr := stampJobsParallel(jobs, userSID)
	mark("stampParallel")
	// Audit each successfully-stamped DENY before the failure check
	// so the JSONL contains the partial pass even when a later path
	// trips the error gate — that's the data a post-mortem needs.
	for _, p := range completed {
		audit.LogMountDecision(sessionID, audit.MountDecision{
			Category: "sensitive",
			Host:     p,
			ReadOnly: false,
			Granted:  false,
			Reason:   "deny_stamp",
		})
	}
	if firstErr != nil {
		audit.LogMountDecision(sessionID, audit.MountDecision{
			Category: "sensitive",
			Host:     firstErrPath,
			Granted:  false,
			Reason:   "deny_failed",
			Err:      firstErr.Error(),
		})
		// Roll back partial stamps so the user is not locked out.
		revokeStampsParallel(completed, userSID)
		_ = os.RemoveAll(scratchDir)
		return nil, fmt.Errorf(
			"restricted: sensitive DENY failed on %s: %w (no DENY applied; verify path ownership)",
			firstErrPath, firstErr)
	}
	return completed, nil
}

// buildBox assembles the box struct from the resolved session parameters.
// Policy overrides from opts are applied here before the box is returned
// to Create.
func buildBox(
	ctx context.Context,
	opts sandbox.CreateOpts,
	sessionID, scratchDir string,
	userSID *windows.SID,
	deniedPaths []string,
) *box {
	policies := DefaultPolicies()
	if opts.BlockNonMicrosoftBinaries != nil {
		// Profile override: compatibility.mitigation_policy.
		// block_non_microsoft_binaries. Default is OFF because the
		// mitigation blocks every third-party DLL load — most dev
		// tools break under it by design. Opt-in only.
		policies.BlockNonMicrosoftBinaries = *opts.BlockNonMicrosoftBinaries
	}
	return &box{
		ctx:         ctx,
		opts:        opts,
		sessionID:   sessionID,
		userSID:     userSID,
		deniedPaths: deniedPaths,
		scratchDir:  scratchDir,
		policies:    policies,
		jobLimits: JobLimits{
			MemoryMB: opts.Resources.MemoryMB,
			MaxPIDs:  opts.Resources.MaxPIDs,
		},
		usePTY: opts.PTY,
	}
}

// LoadPermissionOverrides implements sandbox.PermissionProfileLoader.
// Returns the sandbox-typed overrides for toolName, or (nil, nil) when
// no profile has been saved yet (first run / missing file).
func (b *backend) LoadPermissionOverrides(toolName string) (*sandbox.PermissionOverrides, error) {
	profile, err := LoadPermissionProfile(toolName)
	if err != nil {
		return nil, err
	}
	if profile == nil {
		return nil, nil
	}
	return profile.Overrides.ToSandboxOverrides(), nil
}

// SetStampProgress implements sandbox.StampProgressSetter.
// Wires cb into the parallel stamp hot path. Passing nil clears the callback.
func (b *backend) SetStampProgress(cb func(done, total int)) {
	OnStampProgress = cb
}

// SelfTest implements sandbox.SelfTester: provision a Medium-IL restricted
// token and immediately close it. A failure here usually means the host's
// advapi32 surface is broken (extremely rare; indicates a corrupt Windows
// install). Used by `dizgin doctor`.
func (b *backend) SelfTest() sandbox.SelfTestResult {
	tok, err := CreateRestrictedTokenMediumIL()
	if err != nil {
		return sandbox.SelfTestResult{
			Summary: fmt.Sprintf("CreateRestrictedTokenMediumIL failed: %v", err),
			Hint:    "check Windows error logs; ensure advapi32!CreateRestrictedToken is exported (corrupt Windows install otherwise)",
		}
	}
	defer func() { _ = tok.Close() }()

	sid, err := TokenIntegrityLevelSID(tok)
	if err != nil {
		return sandbox.SelfTestResult{
			Summary: fmt.Sprintf("TokenIntegrityLevelSID failed: %v", err),
			Hint:    "GetTokenInformation(IntegrityLevel) misbehaved on a fresh token; report a bug",
		}
	}
	if sid != IntegrityLevelMediumSid {
		return sandbox.SelfTestResult{
			Summary: fmt.Sprintf("token IL is %s, expected %s", sid, IntegrityLevelMediumSid),
			Hint:    "SetTokenInformation(IntegrityLevel) silently downgraded — report a bug",
		}
	}
	return sandbox.SelfTestResult{OK: true, Summary: "restricted Medium-IL token round-trip OK"}
}

// buildSensitiveDenyJobs converts the SSOT path list into stampJob
// values, filtered to paths that exist on disk. Non-existent paths
// are silently skipped — if the user later creates ~/.ssh during a
// session, the file is not retroactively DENYed (re-stamped on next
// session). A future tightening could add a watcher; for the iter6
// MVP we accept the open window.
//
// overrides (iter6 Phase D) is the per-tool permission profile the
// user authorised on a prior --learn run. SSOT paths listed under
// overrides.RW / overrides.RO are exempted from the DENY sweep so
// the tool gets passthrough access; entries under overrides.Deny are
// stamped in addition to the SSOT so the user can lock down tool-
// specific paths that are not credential-shaped. Nil overrides → SSOT
// applied verbatim (first run or no profile saved yet).
func buildSensitiveDenyJobs(sessionID, userProfile string, overrides *sandbox.PermissionOverrides) []stampJob {
	if userProfile == "" {
		return nil
	}
	paths := security.SensitiveDenyPaths(userProfile)
	jobs := make([]stampJob, 0, len(paths))
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		if isPathExempt(p, overrides) {
			log.DebugSub(log.SubContainer, "restricted: skip DENY %s (user-authorised)", p)
			audit.LogMountDecision(sessionID, audit.MountDecision{
				Category: "sensitive",
				Host:     p,
				Granted:  false,
				Skipped:  true,
				Reason:   "user_authorised",
			})
			continue
		}
		if _, err := os.Stat(p); err != nil {
			if !os.IsNotExist(err) {
				log.DebugSub(log.SubContainer, "restricted: stat sensitive %s: %v", p, err)
			}
			audit.LogMountDecision(sessionID, audit.MountDecision{
				Category: "sensitive",
				Host:     p,
				Granted:  false,
				Skipped:  true,
				Reason:   "not_present",
			})
			continue
		}
		key := strings.ToLower(filepath.Clean(p))
		seen[key] = true
		jobs = append(jobs, stampJob{
			path: p,
			mode: stampModeDeny,
		})
	}
	// User-declared extra DENY entries (overrides.Deny): paths the user
	// wants this specific tool blocked from even when not in the SSOT.
	// Skip duplicates that already came in via the SSOT pass.
	if overrides != nil {
		for _, p := range overrides.Deny {
			key := strings.ToLower(filepath.Clean(p))
			if seen[key] {
				continue
			}
			if _, err := os.Stat(p); err != nil {
				if !os.IsNotExist(err) {
					log.DebugSub(log.SubContainer, "restricted: stat user-deny %s: %v", p, err)
				}
				audit.LogMountDecision(sessionID, audit.MountDecision{
					Category: "user_deny",
					Host:     p,
					Granted:  false,
					Skipped:  true,
					Reason:   "not_present",
				})
				continue
			}
			seen[key] = true
			jobs = append(jobs, stampJob{
				path: p,
				mode: stampModeDeny,
			})
		}
	}
	return jobs
}
