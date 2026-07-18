# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### `dizgin-tui` removed (2026-05-29)

The optional `dizgin-tui` dashboard binary and the `charmbracelet/bubbletea` + `lipgloss` dependency chain (`x/term`, `cellbuf`, `displaywidth`, `uax29`, `coninput`, …) are removed again so the base build ships with just `dizgin` + `dizgind` and a minimal dependency tree. The TUI returns as a deferred, optional binary — see [`docs/ROADMAP.md`](docs/ROADMAP.md) "TUI v2".

**Removed**

- `cmd/dizgin-tui/` (entire package).
- `bubbletea` / `lipgloss` + transitive charm packages from `go.mod` / `go.sum` (`make tidy`).
- `dizgin-tui` build target in `Makefile`.

### iter7 — `dizgind setup` removed (2026-05-19)

The admin-once `dizgind setup` command and its `%ProgramData%\dizgin\setup-marker.json` contract are gone. iter6's restricted token (`CreateRestrictedToken` with empty `SidsToDisable` + `RestrictedSids`) preserves `SeChangeNotifyPrivilege`, which is the privilege NTFS bypass-traversal needs — MSYS2 / Cygwin tools (git, bash) inside dizgin resolve `getcwd()` through the user-profile chain under the user's natural ACL, no host-side ALL APPLICATION PACKAGES grant required.

**Removed**

- `cmd/dizgind/setup_windows.go`, `setup_other.go`, `setup_windows_test.go` (entire `dizgind setup` command + four modes: default, `--check`, `--repair`, `--undo`).
- `internal/platform/setup_windows.go`, `setup_other.go` (`SetupContainerDone` / `MarkSetupContainerDone` / `ClearSetupContainerDone` — only caller was the dead `firstRun` cold-start path in `cmd/dizgin/daemon_check_windows.go`).
- `cmd/dizgin/doctor_windows.go::checkSetupMarker` (and the misleading "Windows volume traversal not stamped" hint it surfaced).
- `cmd/dizgin/diagnostic.go` "dizgind setup" error-hint entry.
- `cmd/dizgin/daemon_check_windows.go` first-run UAC branch + 5-minute cold-start wait. Daemon-autostart now uses the warm-start 15 s cap unconditionally.
- `tests/e2e/setup_then_gitops_windows_test.go` (replaced by `msys2_getcwd_windows_test.go`, same coverage minus the marker gate).
- `tests/e2e/r1_fail_closed_after_setup_windows_test.go` renamed to `r1_fail_closed_windows_test.go`; comment + test name de-coupled from setup.

**Migration**

- Existing users: a stale `%ProgramData%\dizgin\setup-marker.json` is harmless — nothing reads it. Safe to delete.
- Existing volume-root `ALL APPLICATION PACKAGES:(RX)` ACEs from a prior `dizgind setup` are equally harmless. Optional cleanup: `icacls C:\ /remove:g "*S-1-15-2-1" /L /C /Q` (per drive).
- Scripts invoking `dizgind setup --check` / `--repair` / `--undo` will see "unknown command" — drop the call.

**Why this is safe**

- `internal/sandbox/restricted/token_windows.go` calls `CreateRestrictedToken` with `DisableSidCount=0`, `DeletePrivilegeCount=0` (only `LUA_TOKEN` is set indirectly via `DISABLE_MAX_PRIVILEGE`). The user SID's traversal rights are not stripped.
- Grep across `internal/sandbox/restricted/*` for `S-1-15-2-1` and `appcontainer` returns zero matches — the restricted backend never depended on the AC SID grant the setup command was writing.
- Empirically verified: `dizgin -- claude -p` with Bash/Read/Write/Edit all succeeded on a test host where `dizgind setup` had never run.

### iter5 — Bun SEA hang root-cause fix + per-profile compatibility (2026-05-18)

Four-layer surgical pass on top of iter4 targeting CLAUDE-HANG-01
(Bun SEA binaries hanging under AppContainer with CPU-active /
no-output). Each layer is independently revertable via an env-var
emergency switch.

**Added**

- **L1 — Per-session `TEMP` / `TMP` / `TMPDIR` override.**
  `cmd/dizgin/env.go::buildToolEnv` now accepts the AC-SID-stamped
  per-session scratch dir (`box.TempDir()`) and writes it into the
  three temp env vars before handing the env to `box.Start`. Bun
  SEA self-extracts its embedded runtime into `%TEMP%\.bun-fs\` on
  first invocation; with the host `%TEMP%` unreachable under the
  AppContainer DACL the extract silently retries forever. Opt-out
  via `DIZGIN_NO_TEMP_OVERRIDE=1` or
  `compatibility.temp_override: false` in the tool profile.
- **L2 — `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` allowlist.** New
  `internal/sandbox/appcontainer/handle_list_windows.go` registers
  a `0x00020002` PTAL entry listing exactly the three stdio handles
  for the child to inherit. With `bInheritHandles=TRUE` the kernel
  was previously duplicating every inheritable handle in dizgin's
  process table into the child; the explicit allowlist drops
  everything except our owned pipes. PTAL slot count is now dynamic
  (1 with the allowlist disabled, 2 with it on). Opt-out via
  `DIZGIN_NO_HANDLE_LIST=1` or
  `compatibility.handle_list_allowlist: false`.
- **L3 — ETW permissive-learning diagnostic mode.** New
  `internal/sandbox/appcontainer/etw_permissive_windows.go`
  orchestrates `logman.exe` + `tracerpt.exe` (Microsoft-shipped,
  signed) around the child spawn to capture
  `Microsoft-Windows-Kernel-General` keyword `0x20` access-check
  events. Opt-in via `DIZGIN_ETW_PERMISSIVE_LEARN=1`; production
  runs touch zero new syscalls. On child exit, up to 10 `DENIED`
  events plus a count + CSV path land on stderr. Requires admin
  (kernel-mode ETW session); non-admin runs print a clear hint
  and continue silently. Reference: Forshaw / Tyranid
  "Permissive Learning" technique.
- **L4 — Per-profile `compatibility:` block.** New
  `config.Compatibility` struct on `ToolDef` with `*bool` fields
  (`temp_override`, `handle_list_allowlist`, `allow_dynamic_code`,
  `allow_low_label_images`). Unset → fall back to the
  runtime-derived default. The two forward-looking fields parse
  cleanly today (strict-mode YAML stays happy) so a future dizgin
  release that introduces `PROHIBIT_DYNAMIC_CODE` /
  `IMAGE_LOAD_NO_LOW_LABEL` mitigations can ship a profile-level
  escape hatch without breaking older profile files.
  `sandbox.CreateOpts.HandleListAllowlist` wires the profile flag
  into the AppContainer backend.

**Verify state**

- `claude --version` still hangs at the 60 s timeout boundary
  after L1+L2 — at least one further denial point exists.
  CLAUDE-HANG-01 stays **partially mitigated, open**. Iter6
  entrypoint is the L3 ETW trace from an elevated shell.
- `node --version` exits in 750 ms — zero regression on non-Bun
  tools.
- 466 / 442 test PASS (+24 new). `go build`, `go vet`,
  `govulncheck` all clean.

### iter4 — 3-tier R model + sweep (2026-05-18)

**Breaking changes**

- **3-tier R model on `sandbox.Mount`.** Every mount now carries a
  `Category` tag (`workdir` / `declared_rw` / `declared_ro` / `path` /
  `system`). The appcontainer classifier in `backend.Create` routes
  stamps off the tag; the old `ReadOnly` + `IsSystemPath` heuristic is
  gone. Profiles do not need to change — the YAML schema is unchanged
  — but third-party callers constructing `sandbox.Mount` values
  programmatically should set `Category` for forward compatibility.
  `Force` and `Persistent` are deprecated and now no-ops; both are
  kept on the struct for one release window and removed in iter5.
- **Read-only mount permission** narrowed from
  `GENERIC_READ | GENERIC_EXECUTE` to
  `FILE_GENERIC_READ | FILE_TRAVERSE`. The old mask implicitly granted
  binary launch inside read-only mounts via the execute bit; the new
  mask preserves read+descend semantics R1-C requires without the
  junction-redirect attack surface.
- **Web dashboard removed.** `internal/api/` (8 files, ~1.6K LOC),
  `dizgind --web --port --token` flags, and the static asset tree are
  all gone. Use `dizgind status --json` for tooling. Roadmap: a
  Prometheus exporter on opt-in.
- **TUI removed.** `dizgind tui` subcommand and `internal/tui/`
  (12 files, ~2.3K LOC) are gone. `bubbletea`, `lipgloss`, and the
  charmbracelet x/term / cellbuf / displaywidth / uax29 / coninput
  dependency chain are removed from `go.mod`. Use `dizgind status`
  (tabwriter) instead.
- **Userspace DNS proxy removed.** `internal/daemon/dnsproxy_windows.go`
  (~600 LOC) and the `sandbox.CreateOpts.DNSServer` field are gone.
  `network.policy: allowlist` still maps to the AppContainer
  InternetClient capability gate — only the userspace DNS-layer
  enforcement was retired (bypassable by IP literal). Kernel WFP
  allowlist is on the roadmap.
- **`dizgin unstamp` / `dizgin audit-low` removed.** Operator post-incident
  recovery now lives entirely in `dizgind setup --repair` (already
  shipped in iter3). `dizgin`'s help surface focuses on tool execution
  again.
- **5-way exit access prompt removed.** Replaced by a one-line
  post-exit hint plus `dizgin add-path <path>` subcommand. The user
  decides one path at a time on their own schedule instead of
  triaging a wall of paths at session exit.
- **Removed env: `DIZGIN_NATIVE_ACL`.** The dual ACL paths
  (`acl_windows.go` icacls shellout + `acl_native_windows.go`
  `SetNamedSecurityInfo`) consolidated to native-only. The icacls
  path's 280-480 ms-per-call cost is gone; native is now the only
  stamp + revoke implementation.

**Added**

- `dizgin add-path [--tool <name>] [--ro] <path>...` — minimal
  subcommand that appends paths to `~/.dizgin/profiles/<tool>.yaml`.
  Replaces the 5-way exit prompt UI.
- `internal/audit/mount.go::LogMountDecision` — emits one JSONL
  line per stamp decision to `~/.dizgin/audit/<session-id>.jsonl`.
  Opt-out via `DIZGIN_AUDIT_MOUNTS=0`.
- `dizgin doctor` gains a **dizgind setup marker** check on Windows.
  Surfaces "Windows volume traversal not stamped" before MSYS2
  fails with an opaque error.
- `internal/security/path_classify_windows.go` — SSOT for
  `IsSystemPath`, `IsVolumeRoot`, `IsIntegrityDenied`, and
  `DirContainsExecutable`. Closes drift between `backend.go` and
  `integrity_label_windows.go`.
- `internal/sandbox/appcontainer/icacls_helper_windows.go` — SSOT
  for icacls subprocess plumbing (timeout, capture, retry).
- `internal/sandbox/appcontainer/scratch_windows.go` —
  `ScratchRoots()` + `SessionScratchDir()` SSOT consumed by both
  dizgin's allocator and the daemon's orphan sweeper.
- `internal/sandbox/network.go` — `sandbox.NetworkPolicy` type
  alias + `PolicyOpen` / `PolicyAllowlist` / `PolicyBlocked`
  constants. Lets the appcontainer backend drop its direct
  `internal/config` import for the network-policy switch.

**Changed**

- **MSYS / cmd warnings** collapsed from 8 / 6 lines to 1 line each.
  The remediation hint and the `DIZGIN_NO_SHELL_DETECT` opt-out share
  one row so the terminal does not drown in advice.
- **Cold-start hint** now reports elapsed seconds
  ("still preparing AppContainer profile (elapsed 47s)") and points
  at `docs/TROUBLESHOOTING.md#cold-start` past 90 s. Polling tick
  dropped from 500 ms to 50 ms so warm starts return on the first
  heartbeat.
- **Stamp progress renderer** suppresses per-job output when total
  mounts < 20 (warm sessions). Cold storms (≥20) still get the
  `[ stamping N/M (P%) ]` counter.
- **Error decoration** in `cmd/dizgin/diagnostic.go` recognises the
  classifier's `R1-A workdir`, `R1-B declared RW`, `R1-C declared
  RO`, and `dizgind setup` patterns and appends a category-aware
  hint pointing at the right corrective action.

**Removed**

- Files: `internal/api/`, `internal/tui/`,
  `internal/daemon/dnsproxy_windows.go` (+ test),
  `tests/e2e/network_allowlist_windows_test.go`,
  `cmd/dizgin/access_prompt_ui.go` (+ test),
  `cmd/dizgin/access_telemetry_extended_test.go`,
  `cmd/dizgin/incident_recovery_*.go` (Windows + stub),
  `internal/sandbox/appcontainer/acl_windows.go` (+ test).
- Dead code: `peimport.IsPEFile`, `token.LowBoxNtSupported` +
  `procNtCreateLowBoxToken` stub, `profile.SidCapabilities`,
  `integrity_label.stampAncestorTraversal` +
  `revokeAncestorTraversal`, `integrity_label.integrityDenyDirs`
  (moved to `internal/security`), `backend.isSystemPath` (moved
  to `internal/security`), `backend.stagingScratchDir` (moved to
  `appcontainer.SessionScratchDir`).

**Migration**

1. Existing iter3 users: no action needed. `Force` / `Persistent`
   are no-ops; `Mount.Category` is inferred from `ReadOnly` +
   path shape when omitted.
2. Web dashboard users (if any): switch to `dizgind status --json`.
3. TUI users (if any): switch to `dizgind status` (table) or
   `dizgin doctor` for health checks.
4. Anyone running `dizgin unstamp` or `dizgin audit-low` in scripts:
   replace with `dizgind setup --repair`.

### Breaking changes
- **Install requires admin once.** First-time setup now runs
  `dizgind setup` (UAC prompt) to stamp every fixed-drive volume
  root plus `C:\Users\` with a non-inheriting
  `ALL APPLICATION PACKAGES:(RX)` ACE. This is the load-bearing fix
  for R2-02 (MSYS2 `getcwd()` failing under AppContainer); without
  it MSYS2-based tools (git, bash) cannot resolve the working
  directory inside a dizgin session. The grant is non-inheriting —
  descendants are unaffected, no Low IL leakage. Subsequent `dizgin`
  invocations run as a regular user with no further UAC prompts.
  Migration: run `dizgind setup` once. `dizgind setup --check`
  reports state without admin; `dizgind setup --repair` audits and
  reverts any Low IL drift left by earlier R&D builds; `dizgind setup
  --undo` rolls the grants back if needed.
- **Removed daemon stamp brokerage.** The IPC paths `stamp_paths`
  and `revoke_sid` and their handlers, the persistent stamp marker
  cache under `%ProgramData%\dizgin\stamp-cache`, the orphan stamp
  sweeper, the `SystemMountDelegator` registration, and the
  `dizgin -> daemon` round-trip for tool DLL + system mount grants are
  all gone. AppContainer DACL stamping is now fully in-process
  inside dizgin's parallel mount worker pool. Profiles that previously
  named TrustedInstaller-owned RW paths (rare, explicit
  `Persistent=false`) will now surface `icacls` AccessDenied at
  session start — the user can adjust the profile or escalate via
  the new dedicated tool. Mount-list YAML schema unchanged
  (`persistent: true` becomes a no-op for the AppContainer backend
  and is now treated as an audit-only hint).
- **Closed R2-02.** With `dizgind setup` in place, MSYS2 `getcwd()`
  resolves cleanly through the user-profile chain inside
  AppContainer sessions. Previous deferral to v0.1.1 is no longer
  needed. The defensive denylist in
  `internal/sandbox/appcontainer/integrity_label_windows.go` and
  the auto-walk traversal helper stay as belt-and-braces (the
  helper is no longer invoked from `backend.go::Create`).

### Added
- **`dizgind setup`** — admin-once Windows command with four modes:
  default install, `--check` (read-only state probe), `--repair`
  (Low IL audit + revert + install), `--undo` (revoke setup-time
  grants + erase marker). Marker at
  `%ProgramData%\dizgin\setup-marker.json` is idempotent + schema
  versioned. Non-Windows stub prints a one-line "not required"
  message and exits 0.
- **`dizgin` cmd /c warning.** `dizgin -- cmd /c "<line>"` now emits a
  one-time stderr hint suggesting `dizgin run "<line>"` instead, which
  bypasses argv reassembly and hands the command line to cmd
  verbatim. Opt-out via `DIZGIN_NO_SHELL_DETECT=1`.
- **R1 regression test** (`tests/e2e/r1_fail_closed_after_setup_windows_test.go`) —
  asserts that a sandboxed `powershell -c Set-Content C:\Windows\Temp\…`
  is denied even with the new setup-time volume-root grant. Confirms
  the non-inheriting flag isolates the traversal grant from
  descendants.
- **Post-setup happy-path test** (`tests/e2e/setup_then_gitops_windows_test.go`) —
  `dizgin git status` succeeds inside a throwaway repo. Replaces the
  deferred R2-02 known issue with a positive end-to-end check.

### Security
- **Breaking — Low IL labeling no longer a side effect of mount stamping.**
  Earlier R2-02 R&D applied an `(OI)(CI)L` (Low mandatory label, object +
  container inherit) SACL ACE to every directory that received the
  AppContainer DACL grant. The OI/CI inheritance silently propagated Low
  IL into user PATH dirs (`~/.local/bin`, `~/.cargo/bin`, …) and config
  trees (`~/.claude`, 32K files), breaking subsequent launches of PATH
  binaries (claude, node, rtk, …) and leaving a latent time bomb across
  the user profile. The Low-label side effect has been removed from
  `StampPathForAppContainer` and `stampPathNative`; integrity labeling is
  now opt-in via the dedicated `stampIntegrityLabel` helper, which
  refuses denylisted paths.
- **New ancestor-traversal denylist.** `stampAncestorTraversal` is no
  longer invoked automatically from `backend.go::Create`. The helper
  itself now consults `checkIntegrityStampAllowed`, refusing PATH
  directories, volume roots, `%SystemRoot%`, `%ProgramFiles%(x86)`,
  `%ProgramData%`, `~/.local/bin`, `~/.cargo/bin`, `~/go/bin`,
  `~/AppData/Local/Programs`, `~/AppData/Roaming/npm`,
  `~/AppData/Roaming/Microsoft/WindowsApps`, `~/bin`, `~/scoop`,
  `~/.claude`, `~/.gemini`, `~/.codex`, `~/.cursor`, `~/.config`,
  `~/.ssh`, and any directory containing executable files.
- **Recovery tooling — `dizgin unstamp` and `dizgin audit-low`.**
  - `dizgin unstamp <path> [-r] [-y]` — reverts the mandatory label SACL on
    `<path>` to Medium; `-r` recurses via icacls `/T` with an interactive
    `YES` confirmation gate (skippable with `--yes` for scripts).
  - `dizgin audit-low [<root>]` — walks `<root>` (default
    `%USERPROFILE%`) and lists every directory whose SACL carries a Low
    mandatory label ACE. Skips `.git`, `node_modules`, `Temp`, `tmp`.
  Both commands are Windows-only stubs that fail loudly on macOS/Linux.

### Added
- Failsafe unit tests in `internal/sandbox/appcontainer/acl_native_windows_test.go`:
  `TestStampPathNative_DoesNotWriteLowLabelACE`,
  `TestCheckIntegrityStampAllowed_VolumeRoot`,
  `TestCheckIntegrityStampAllowed_UserConfigDir`,
  `TestCheckIntegrityStampAllowed_SystemDirs`,
  `TestCheckIntegrityStampAllowed_PathDir`,
  `TestCheckIntegrityStampAllowed_FreshTempDir`,
  `TestCheckIntegrityStampAllowed_TempDirWithExe`,
  `TestStampIntegrityLabel_RefusesDenylistedPath`.
- Root `SECURITY.md`, `CODE_OF_CONDUCT.md`, GitHub `CODEOWNERS`, PR
  template, bug-report and feature-request issue templates,
  security-disclosure stub, and Issue config that gates blank issues.
- Dependabot config for `gomod` + `github-actions` (weekly, grouped
  minor+patch).
- CodeQL workflow (`.github/workflows/codeql.yml`) — weekly + on push
  to main.
- Release workflow (`.github/workflows/release.yml`) — GoReleaser
  triggered on `v*.*.*` tag.
- Locale-agnostic access telemetry: `NoteFromArgs` fallback flags
  every absolute-path argv element that does not exist on the host
  filesystem when the tool exits non-zero, so missing-path detection
  works on every Windows locale (Türkçe, Deutsch, 日本語, …) and not
  just English.
- Multi-locale fixture tests for the access-telemetry regex layer.
- `DIZGIN_NO_DAEMON_AUTOSTART=1` env var bypasses dizgind autostart for
  test harnesses.
- `tests/e2e/main_test.go` — `TestMain` configures the e2e suite
  environment so the suite stops hanging on missing daemons.
- `internal/log` and `internal/sandbox/appcontainer` happy-path tests
  to lift critical-path coverage.

### Changed
- `ensureDaemonRunning` warm-start wait reduced from 60 s to 15 s; the
  5-minute first-run path is unchanged.
- `Makefile` `e2e:` target now stages the freshly-built `dizgin` and
  `dizgind` binaries into `tests/e2e/testdata/` so the integration
  suite stops silently SKIPping. Test timeout raised from 120 s to
  300 s.
- `docs/CONFIG.md` documents the `ipc:` profile field as
  informational-only — runtime backend selection is platform-driven.
- HCS-era progress log moved to `docs/history/progress-hcs.md`;
  `docs/progress.md` rewritten as an active-state summary.

## [0.1.0] — 2026-02-28

Initial release — Windows MVP with full HCS Container sandbox, macOS seatbelt, Linux bubblewrap.

### Added

#### Core
- `dizgin` — transparent sandbox wrapper with environment and flag passthrough
- `dizgind` — orchestration daemon with Bubbletea TUI (session list, credential manager)
- `dizgin version` — print version/commit/date
- `dizgin update` — self-update from GitHub releases with SHA-256 checksum verification
- `dizgind setup` — Windows HCS container setup with auto-elevation via UAC (automatic on first launch)
- `-w / --workdir` flag for working directory override

#### Sandbox Backends
- **Windows**: HCS Container — process isolation (Hyper-V fallback), per-directory bind mounts, ConPTY support, container resource limits (memory, CPU, PID count)
- **macOS**: Seatbelt — `sandbox-exec` SBPL profiles, read-only system mounts, network allowlist via domain rules
- **Linux**: bubblewrap — user namespace isolation, seccomp-BPF deny-list (20+ blocked syscalls), per-path bind mounts

#### Configuration
- YAML config (`dizgin.yaml`) with auto-discovery (workdir → `$XDG_CONFIG_HOME` → `~/.config/dizgin`)
- Per-tool defaults for: `claude`, `codex`, `aider`, `gemini`, `opencode`
- Filesystem policy: `read_write`, `read_only`, `tmp_size`, `zero_residue`
- Network policy: `open`, `allowlist`, `blocked`
- Resource limits: `memory_mb`, `cpu_percent`, `max_pids`, `timeout`
- Credential config: SSH agent forwarding, API key injection, GitHub token, git identity

#### Credentials
- SSH agent socket forwarding (key never enters sandbox)
- API key injection via environment (Anthropic, OpenAI, Gemini, Groq, Azure OpenAI)
- GitHub token resolution (env: `GITHUB_TOKEN`, `GH_TOKEN`, `gh` CLI config, git credential store)
- Git identity detection (name, email from git config)
- macOS Keychain lookup via `security` CLI
- Linux GNOME Keyring lookup via `secret-tool`

#### Daemon / IPC
- Named pipe transport on Windows (`\\.\pipe\dizgind`, DACL owner-only)
- Unix socket transport on Linux/macOS (`$XDG_RUNTIME_DIR/dizgind.sock`, 0600)
- IPC message types: `register`, `heartbeat`, `deregister`, `command`, `query_status`, `shutdown`
- `dizgind stop` / `dizgind status` subcommands

#### TUI (`dizgind`)
- Session list with live status (running / suspended / dead)
- Suspend/resume (`s`), kill selected (`x`), kill all (`K`)
- Credential manager tab (Space to toggle)
- Read-only remote mode when daemon is already running
- Keyboard shortcut help (`?`)

#### Install Scripts
- `scripts/install.ps1` — Windows PowerShell (downloads + installs `dizgin` + `dizgind`)
- `scripts/install.sh` — Linux/macOS shell script

#### CI/CD
- GitHub Actions CI on `windows-latest`: lint → test → build
- GoReleaser v2 — Windows/macOS/Linux amd64+arm64 (Windows arm64 excluded)

[Unreleased]: https://github.com/sungurerdim/dizgin/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sungurerdim/dizgin/releases/tag/v0.1.0
