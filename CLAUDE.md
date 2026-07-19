# DIZGIN — Project Instructions

Platform-native, tool-agnostic sandbox wrapper + orchestration daemon for AI coding tools.
Module: `github.com/sungurerdim/dizgin`

## Stack

Go 1.25+ · cobra v1.10 · viper v1.21 · creack/pty v1.1 · go-winio v0.6 · golang.org/x/sys v0.44 · Build: GoReleaser v2 · Lint: golangci-lint v2.12 · CI: none (no-CI policy; gates run locally).

(Iter4 retired bubbletea + lipgloss and the charmbracelet x/term /
cellbuf / displaywidth / uax29 / coninput chain alongside the
`dizgind tui` removal. A standalone `cmd/dizgin-tui/` binary briefly
reintroduced that chain in iter7; it was removed again 2026-05-29 so
the base build ships with just `dizgin` + `dizgind`. See `docs/ROADMAP.md`
for the deferred TUI v2 plan.)

## Binaries

- **dizgin** — sandbox wrapper. Own flags: `-w/--workdir`, `-c/--config`, `--profiles`, `--no-pty`, `--learn`, `-h`, `-v`. `DisableFlagParsing: true` on cobra root + manual `parseOwnFlags()` strips own flags before the tool boundary so all other flags pass through transparently. Subcommands: `version`, `completion`, `doctor`, `add-path`, `run`, `update`, `diagnose-hang`. Entry: `cmd/dizgin/main.go` → `run()` → `backend.Create()` → `box.Start()`.
- **dizgind** — orchestration daemon. Session mgmt, credential discovery, suspend/resume. Subcommands: `start`, `stop`, `status`, `completion`, `heal` (Windows: DACL drift scan + `--apply` revoke; no-op stub elsewhere — `cmd/dizgind/heal_windows.go` / `heal_other.go`, registered via `init()`). Entry: `cmd/dizgind/main.go`.

Sandbox backends (registry pattern, `Backend` + `Box` interfaces, init-based registration): Restricted Token + Medium IL + Job (Windows), Seatbelt (macOS), bubblewrap (Linux). One backend per platform; **no fallback**.

## Modules

- `internal/sandbox/` — `interface.go` (Backend+Box+`MountCategory`), `registry.go`, `network.go` (sandbox-level NetworkPolicy alias)
- `internal/sandbox/restricted/` — Windows iter6 backend: `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` + Medium IL (`S-1-16-8192`) + Job Object + per-child Process Mitigation Policies (DEP/ASLR ON, ACG OFF) + DACL DENY ACEs on sensitive paths via `SetNamedSecurityInfo`.
- `internal/sandbox/seatbelt/` — macOS `sandbox-exec` SBPL profiles
- `internal/sandbox/bubblewrap/` — Linux bwrap + seccomp-BPF
- `internal/daemon/` — IPC server/client (named pipe / unix socket), session registry, orphan scratch sweeper
- `internal/config/` — YAML config + tool profiles + auto-detection
- `internal/credential/` — SSH agent / API keys / GitHub token / git identity / Win Cred Manager
- `internal/netfilter/` — user-mode WFP network allowlist enforcement (`wfp_windows.go`: dynamic-session engine + app-id-scoped block(v4/v6) + per-IP permit filters inside one transaction; `wfp_other.go` stub). Brokered by the **elevated dizgind daemon** (`TypeWFPApply`/`TypeWFPRevoke` IPC) because dizgin is non-elevated and lacks `FWPM_ACTRL_ADD`. dizgin drives it from `cmd/dizgin/netfilter.go` (apply after start, revoke at teardown; `DIZGIN_NO_WFP=1` disables → advisory). Accidental-egress protection, not hostile-tool (same-SID can delete its own filters); kernel-driver enforcement is ROADMAP #1.
- `internal/audit/` — JSONL session log + per-session `mount.LogMountDecision` writer (`~/.dizgin/audit/<sid>.jsonl`)
- `internal/security/` — risky-path filter, user deny-list, `path_classify_windows.go` (system/volume/integrity classifier), `sensitive_paths_windows.go` SSOT (DENY-ACE target list: `.ssh`, `.aws/credentials`, `.gnupg`, browser cookies, DPAPI vault, …)
- `internal/diagnostic/wct/` — Wait Chain Traversal helper used by `dizgin diagnose-hang` (extracted from the appcontainer package in iter6 Phase 4)
- `internal/depclosure/` — dynamic shared-library dependency-closure resolver. Parses a binary's real load commands (Mach-O `LC_LOAD_DYLIB`/`LC_RPATH` via `debug/macho` on Darwin; ELF/DT_NEEDED deferred on Linux, `depclosure_other.go` no-ops there) and returns the on-disk files it actually links against, recursively, bounded by a node/depth cap + deadline. `cmd/dizgin/mounts.go`'s `addDepClosureMounts` seeds it with the tool's own binary plus every executable in the PATH-mounted dirs (git, node, python, …) and mounts each resolved dependency as a single RO file (`sandbox.CategoryDepClosure`) — replacing per-tool guesswork (a hand-authored profile enumerating "Homebrew's pcre2 lib lives at /opt/homebrew/opt/pcre2/lib") with asking the binary itself.
- `internal/platform/` · `internal/monitor/` · `internal/log/`

## Interfaces

```go
type Backend interface {
    Name() string
    Available() bool
    Create(ctx context.Context, cfg *config.Config, opts CreateOpts) (Box, error)
}
type Box interface {
    Start(ctx context.Context, cmd string, args []string, env []string) error
    Wait() (int, error)
    Signal(sig os.Signal) error
    PTY() io.ReadWriteCloser
    Cleanup() error
}
```

## Tool Resolution

1. YAML override → `dizgin.yaml` `tools:` section
2. Profile files → bundled `profiles/*.yaml` + user `~/.dizgin/profiles/`
3. Auto-detect → `~/.toolname` exists → mount; `TOOLNAME_API_KEY` set → inject

`sandbox_path == host_path` on every platform — no path translation.

## Daemon IPC

JSON over named pipe (Windows: `\\.\pipe\dizgind`) / unix socket (Linux/macOS: `0600` + `SO_PEERCRED`):
- `register` / `heartbeat` / `deregister` — session lifecycle
- `command` — daemon → instance (suspend/resume/kill)
- `wfp_apply` / `wfp_revoke` — dizgin → elevated daemon: install / tear down the user-mode WFP network allowlist for a session (dizgin is non-elevated; the daemon holds `FWPM_ACTRL_ADD`)

Iter3 (2026-05-18) removed the `stamp_paths` / `revoke_sid` RPCs. iter6 went one step further: the AppContainer backend was retired entirely (CLAUDE-HANG-01 root cause: ACG ↔ Bun JIT collision), so there is no AC-SID grant work to broker at all. iter7 (this commit) deleted `dizgind setup` because the restricted backend's token preserves `SeChangeNotifyPrivilege` and NTFS traversal works without any volume-root ALL APP PKG grant — no admin-once setup remains; dizgin runs from cold install with zero UAC prompts. (ds-ship pass, 2026-07-19) removed the `launch` / `remote_command` RPCs and the `Launcher` type — dead since the TUI's iter4 removal, zero production callers.

## Development

```bash
make build | test | lint | fmt | tidy
make e2e            # integration suite (windows/restricted)
make hooks-install  # wire scripts/git-hooks → core.hooksPath (pre-commit + pre-push)
make release              # gated single-command release, version auto-detected (see CONTRIBUTING.md)
make release TAG=vX.Y.Z   # or pin the version explicitly
```

Quality gates: `go vet ./...` · `golangci-lint run` · `go test ./...` · `go build ./cmd/dizgin ./cmd/dizgind`. Once `hooks-install` is run, the `pre-push` hook (`scripts/git-hooks/pre-push` → `scripts/pre-push.{sh,ps1}`) enforces this full set plus `govulncheck` and `make e2e` on every push, not just releases.

Test escape hatches / emergency switches:
- `DIZGIN_NO_DAEMON_AUTOSTART=1` — skip dizgin's auto-spawn of dizgind.
- `DIZGIN_DISABLE_PATH_MOUNTS=1` — skip RO mounts for every host PATH dir.
- `DIZGIN_NO_WFP=1` — disable user-mode WFP network-allowlist enforcement → advisory.
- `DIZGIN_NO_AUTO_GRANT=1` — disable the zero-config auto-grant of RO for non-sensitive denied paths (the accessRecorder is then only created for explicit `--learn`).
- `DIZGIN_NO_SUGGEST=1` — disable the LLM enrichment call in `dizgin add-path --suggest` (no network; heuristic mode only). Use in air-gapped or offline environments.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | success |
| 1 | tool error |
| 126 | tool not in PATH |
| 127 | backend unavailable |
| 128+N | killed by signal N |

## Security Model — Red Lines

**R1 — Sensitive Surface Isolation.** iter6 flipped the iter5 model: instead of declaring an allowlist of permitted paths and DENY-by-default everywhere else (the AppContainer model), iter6 declares a small DENY-list of high-value credential surfaces and lets the user's natural NTFS permissions cover everything else.

- **R1-DENY (sensitive)** — Hardcoded SSOT in `internal/security/sensitive_paths_windows.go`: `.ssh`, `.aws/credentials`, `.aws/config`, `.gnupg`, `.netrc`, `.docker/config.json`, `.kube`, `.git-credentials`, `.config/gh/hosts.yml`, `.azure` (Azure CLI MSAL token cache), `.config/gcloud` (GCP ADC + access tokens), `.terraform.d/credentials.tfrc.json` (Terraform Cloud token), CryptoAPI RSA/DSS key store (`AppData/Roaming/Microsoft/Crypto`), DPAPI master keys + CREDHIST (`AppData/Roaming/Microsoft/Protect`), Win Credential Manager (`AppData/Local/Microsoft/Credentials`), Win Vault, Chrome/Edge/Firefox cookie stores. Each existing path receives a DENY ACE (`SetEntriesInAcl` GENERIC_ALL with OI+CI inheritance) on session start; revoked tree-walking on session end via `SET_ACCESS` (REVOKE_ACCESS asymmetry: SetEntriesInAcl only strips allow ACEs, not deny — SET_ACCESS strips both).
- **R1-USER** — `C:\Users\<self>\*` minus the DENY set is RW by the user's own NTFS rights. The restricted token runs as the same user as dizgin, so no explicit GRANT is needed.
- **R1-SYSTEM** — `C:\Windows`, `C:\Program Files\*`, `C:\ProgramData\*` are RO by the user's natural permissions; admin-required writes hard-fail.
- **R1-OTHER-USERS** — `C:\Users\<other>\*` is denied by Windows' own NTFS ACEs (different user SID), no extra work.

**R2 — Native Experience.** Sandbox is transparent to the tool: REPL, named pipes, MCP, git all functional. `host_path == guest_path`, no path translation.

**Fail-closed with actionable hint.** Partial DENY application aborts session creation under R1 — a half-stamped tree is worse than no tree (rolling back the successful stamps + removing the scratch dir + clear error).

### Defense layers

Production Windows backend (iter6) = restricted token (`CreateRestrictedToken DISABLE_MAX_PRIVILEGE` + Medium IL `S-1-16-8192`; **no** SidsToDisable / RestrictedSids so NTFS `SeChangeNotify` traversal stays alive) + Job Object (kill-on-close, memory cap, PID cap, UI restrictions) + per-child Process Mitigation Policies via `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` PTAL (DEP ON, ASLR force-relocate + high-entropy + bottom-up ON, ImageLoad NoRemote/NoLowLabel/PreferSystem32 ON, StrictHandleChecks ON, **ACG OFF** because Bun's in-process JIT collapses against ACG — that was CLAUDE-HANG-01) + DACL DENY ACEs on the sensitive SSOT. macOS = kernel-MAC Seatbelt (SBPL) with an R1 credential-deny block (last-match-wins, symlink-canonical paths) + IP-resolved network allowlist. Linux = user-namespace + seccomp-BPF with R1 cover-mounts (0000 tmpfs / empty-file shadows) for sensitive paths that fall under a declared mount. The sensitive SSOT (`internal/security/sensitive_paths_{windows,darwin,linux}.go`) and the per-tool permission override loader (`internal/permissions`) are now cross-platform. None claims hypervisor isolation; all are production-tested. (Cross-platform R1 shipped in the dizgin OS-parity pass; the full interactive `--learn` flow and Linux filtered-egress allowlist remain Windows-only / deferred — see ROADMAP.)

### Enforcement

- **FS** — DACL DENY ACEs on the sensitive SSOT, applied in-process via `SetNamedSecurityInfo`. Revoke walks the tree with `SET_ACCESS` (zero perms) to remove both DENY and any GRANT entries (REVOKE_ACCESS in SetEntriesInAcl only strips ACCESS_ALLOWED — documented asymmetry). Volume roots + `C:\Users\` get a non-inheriting `ALL APPLICATION PACKAGES:(RX)` ACE via `dizgind setup` (admin-once) for MSYS2 `getcwd()` traversal compatibility; the restricted backend itself doesn't need the grant but keeping it preserves backwards compatibility with anything that does.
- **Network** — `open` / `allowlist` / `blocked` are profile-declared. On Windows a non-empty `allowlist` is now enforced by a user-mode WFP filter set (`internal/netfilter`), brokered through the elevated dizgind daemon: an app-id-scoped block at `ALE_AUTH_CONNECT_V4/V6` + a permit per resolved IP, inside a dynamic WFP session that auto-reaps on revoke. This is accidental-egress protection (a same-SID process can delete the filters); a kernel-mode callout driver (ROADMAP #1) is the hostile-tool-grade path. `DIZGIN_NO_WFP=1` reverts to advisory. CIDR entries are unsupported in the interim (logged, not silently dropped). Linux `allowlist` is not yet enforced at all — `bubblewrap.Create()` always rejects it (fail-closed, no silent downgrade to `open`); only `blocked`/`open` are enforced today.
- **Resources** — Job Object (`JOB_OBJECT_LIMIT_PROCESS_MEMORY` / `_ACTIVE_PROCESS`), Linux cgroups, mac rlimit (`RLIMIT_NPROC` for `max_pids` only — Darwin's kernel rejects a finite `RLIMIT_AS`, so `memory_mb` is not enforced on macOS). Default `resources.timeout=30m` caps runaway loops.
- **Privileges** — `security.no_new_privileges` / `drop_all_caps` are Linux-only (`--unshare-user` yields cap=0 in the new namespace); Windows + macOS no-op (kept for cross-platform YAML portability).
- **Credentials** — SSH agent socket forwarded (key never enters sandbox), API keys via `0600` temp env injection, multi-source GitHub token resolution.
- **IPC** — anonymous pipe SDs grant the user SID GENERIC_ALL (simpler than the iter5 acStdio that needed AC SID + user SID); pipe handles inherited via `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` PTAL so only the three stdio handles cross the parent/child boundary.

No host-side admin-once setup is required. iter6's restricted token retains `SeChangeNotifyPrivilege` (`SidsToDisable` + `RestrictedSids` are both empty in `CreateRestrictedToken`), so NTFS bypass-traversal works against every directory the user already has on their volume. MSYS2 / Cygwin tools (git, bash) inside dizgin sessions resolve `getcwd()` through the user-profile chain without any explicit ALL APPLICATION PACKAGES grant on volume roots. (iter5 needed that grant because AppContainer tokens carry an AC SID that does **not** have natural traversal; iter6 went back to a same-user token and the problem dissolved.)

### Phase 5 — Permission Learning (--learn)

`dizgin --learn -- <tool>` keeps the DENY ACEs in place but wraps the child's stderr with an access-denial recorder. After the tool exits, dizgin:

1. Prints a summary of captured denial lines (locale-aware: matches English, Turkish "engellendi", German "verweigert", Spanish "denegado") via `PrintLearnSummary` (`learn_prompt_windows.go`).
2. Extracts absolute paths from those lines via `accessRecorder.PathHits` (`learn_windows.go`).
3. If stdin is a TTY, prompts the user to classify each path (`rw` / `ro` / `deny` / `skip`) via `PromptForPermissions` (`learn_interactive_windows.go`).
4. Persists the decisions to `~/.dizgin/permissions/<tool>.yaml` via `SavePermissionProfile` (`permissions_windows.go`).

On subsequent normal runs (no `--learn`), `dizgin` auto-loads the per-tool YAML via `loadPermissionOverrides` (`cmd/dizgin/permissions_windows.go`) and passes the `RW`/`RO`/`Deny` lists into `backend.Create`. `buildSensitiveDenyJobs` skips SSOT paths the user authorized as RW/RO and adds extra DENY ACEs for paths the user declared `Deny`. Non-TTY contexts (piped stdin, CI) degrade to skip — the summary still prints, but no prompt fires and no file is written.

**Zero-config auto-grant (Phase 4c).** On a NORMAL run (no `--learn`) the same `accessRecorder` stays active (unless `DIZGIN_NO_AUTO_GRANT=1`). At exit, denied paths are auto-classified (`learn_auto_windows.go`): a non-sensitive path gets an automatic **read-only** grant persisted to `~/.dizgin/permissions/<tool>.yaml` so the next run just works; a sensitive-SSOT path (`security.IsSensitiveDeny`) is **never** auto-granted — TTY prompts the sensitive subset, non-TTY skips with a summary. Two invariants enforced by `autoGrantSafe`: R1 is never auto-relaxed (sensitive needs an explicit decision) and RW is never auto-granted (auto path only ever adds RO).

## CI/CD

**No CI** — the `.github/workflows/` pipelines (ci/codeql/release) were removed under a no-CI policy. Quality gates run locally before merge: `gofmt`, `go vet`, `golangci-lint` v2 (govet/errcheck/staticcheck/ineffassign/unused + **gosec** + **gocritic**; gosec excludes the syscall-backend-inherent rules — see `.golangci.yml`), `go test -race` (windows/ubuntu/macos), `go build` (5-arch), `govulncheck`. Releases are cut manually via `make release` (`scripts/release.sh`, GoReleaser under the hood — `.goreleaser.yml`), which gates dirty-tree state, version resolution (auto-detected from Conventional Commits since the last release tag, or `TAG=vX.Y.Z` to override), the full push-time validation set (exactly once), a 7-day-cadence heavy layer (coverage threshold + cross-platform artifact build), the deploy itself, and a post-deploy verify-live check against the published GitHub release; see CONTRIBUTING.md "Cutting a Release". A gate-free `make release-raw CONFIRM=yes` escape hatch exists for emergencies only. Artifact signing is not configured (see the note in `.goreleaser.yml`).

## Recently closed issues

- **Iter6 (2026-05-18) — AppContainer → `restricted` backend migration; CLAUDE-HANG-01 RESOLVED.** Windows AppContainer implicitly forces ACG (Arbitrary Code Guard), which hard-blocks Bun's in-process JIT — the structural cause of `claude --version` hanging under dizgin. The `restricted` backend (`CreateRestrictedToken DISABLE_MAX_PRIVILEGE` + Medium IL + Job + per-child Process Mitigation Policy bitfield with **ACG explicitly OFF**) replaces it entirely; Bun-class JIT runtimes now load cleanly. Sensitive-path DACL DENY moved to this backend too (`internal/security/sensitive_paths_windows.go` SSOT, 19 paths today; revoke uses `SET_ACCESS` with 0 perms — `SetEntriesInAcl`'s `REVOKE_ACCESS` only strips allow ACEs, so a plain revoke would leave the DENY stamped). AppContainer package deleted (-5800 LOC net; WCT diagnostic survives at `internal/diagnostic/wct/`). `--learn` shipped in full: locale-aware stderr denial scan → TTY prompt → YAML persistence at `~/.dizgin/permissions/<tool>.yaml`, auto-loaded on the next run. E2E-verified: sensitive DENY blocks the child, then `~/.ssh` is accessible again after dizgin exits (revoke walk works). 630 `func Test` today (3-OS). See [`docs/iter6-tasks.md`](docs/iter6-tasks.md) for the full historical plan.
- **Iter5 (2026-05-18) — Bun SEA hang mitigation layers, later closed by iter6.** Two of the four defense layers are still live in the current `restricted` backend: per-session `TEMP`/`TMP`/`TMPDIR` redirect (Bun's `$bunfs` extract needs a writable target — `DIZGIN_NO_TEMP_OVERRIDE=1` to disable) and a `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` PTAL entry so only the three stdio handles inherit into the child (`DIZGIN_NO_HANDLE_LIST=1` to disable). A third layer — an opt-in ETW permissive-learning trace via `logman`/`tracerpt` — was removed along with the AppContainer backend and no longer exists; ignore any reference to `DIZGIN_ETW_PERMISSIVE_LEARN` in older notes. The actual hang root cause (ACG blocking Bun's JIT) was only found and fixed in iter6 — see that entry. Historical detail: [`docs/known-issues/claude-bun-sea-hang.md`](docs/known-issues/claude-bun-sea-hang.md).
- **Iter4 (2026-05-18) — 3-tier R model + marginal-feature sweep + UX overhaul.** Net ~6.9K LOC removed (web dashboard, TUI, userspace DNS proxy, 5-way exit prompt, dual ACL paths, dead stubs) for ~620 LOC added (SSOT helpers, audit/mount, `dizgin add-path`, 3-tier classifier). DACL stamping consolidated to native `SetNamedSecurityInfo` (icacls path retired).
- **R2-02 (iter3 → iter7 removed entirely).** iter3 made MSYS2 `getcwd()` work inside AppContainer by stamping volume roots via `dizgind setup`. iter6 retired AppContainer; iter7 deleted `dizgind setup` outright — the restricted token's preserved `SeChangeNotifyPrivilege` makes the host-side grant unnecessary. A stale marker from a pre-iter7 build is harmless and never read.
- **R2-01 (2026-05-06).** AppContainer child stdio loss under `--no-pty` was resolved via AC-SID-granted owned pipes; moot since AppContainer's iter6 retirement.
- **Post-execution cleanup hang (2026-05-15).** Hard timeouts on every `icacls` call (15s daemon, 10s dizgin) plus a 5s `runWithDeadline` guard around `DeleteProfile` in `box.Cleanup`. Detail: [`docs/known-issues/post-execution-cleanup-hang.md`](docs/known-issues/post-execution-cleanup-hang.md).

## Blueprint Profile

Type: devtool/CLI | Stack: Go 1.25 (cobra, viper, go-winio, creack/pty, x/sys) | Target: production
Mission: minimize the risk of running AI coding tools with full host access via real OS-native sandboxing while preserving native tool experience
Priorities: Security, Code Quality | Constraints: single backend per OS (no fallback), host_path==guest_path, minimize deps
Red lines: never silently fall back when isolation can't be established (R1), never break native tool experience for sandboxing (R2)
Integrations: none
Data: credential surfaces (SSH/AWS/GCP/Azure tokens, DPAPI, browser cookies); no PII collection | Regulations: none
Audience: developers | Deploy: GitHub Releases (GoReleaser)

Entry: cmd/dizgin/main.go (cobra, DisableFlagParsing) + cmd/dizgind/main.go (daemon)
Modules: internal/sandbox=backends+restricted/seatbelt/bubblewrap(registry); internal/daemon=IPC+session-registry; internal/config=YAML+profiles; internal/credential=ssh/api/github/git; internal/netfilter=user-mode WFP; internal/security=path-classify+sensitive SSOT; internal/audit=JSONL; internal/platform; internal/monitor; internal/log; internal/diagnostic/wct
Data Flow: dizgin CLI -> parseOwnFlags -> backend.Create -> box.Start -> sandboxed child (token+IL+Job+DACL DENY)
External: cobra(CLI); viper(config); go-winio(named pipe); creack/pty(unix pty); x/sys(Windows/Linux syscalls)
Toolchain: gofmt, golangci-lint v2 (+gosec+gocritic), go test -race, govulncheck | CI: none (local gates) | Container: none
Ideal: coupling=low cohesion=high complexity<=15 coverage=70%

Scores: sec=93 quality=88 arch=85 perf=92 resil=92 test=90 stack=85 dx=95 docs=88 overall=90 model=claude-sonnet-5

## End Blueprint Profile

## Future Work

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for deferred features
(TUI v2, WFP DNS allowlist, post-incident recovery v2),
active R&D (shimV2 Hyper-V tier, Linux
Landlock, macOS Endpoint Security), and explicit non-goals (Docker
integration, FUSE, path translation).

## See also

- [`docs/SECURITY.md`](docs/SECURITY.md) — full red-line evidence map.
- [`docs/CONFIG.md`](docs/CONFIG.md) — config YAML reference.
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — deferred features + future work.
- [`docs/progress.md`](docs/progress.md) — active progress + roadmap.
- [`docs/history/`](docs/history/) — archived HCS-era progress + per-run audit history.
