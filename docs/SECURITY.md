# Security

## Sandbox Isolation Guarantees

### Windows — Restricted Token + Medium IL + Job + DACL DENY

| Property | Guarantee |
|----------|-----------|
| Filesystem | DACL DENY ACEs on a hardcoded SSOT of credential surfaces (`internal/security/sensitive_paths_windows.go`: `.ssh`, `.aws/credentials`, `.gnupg`, `.netrc`, `.docker/config.json`, `.kube`, `.git-credentials`, `.config/gh/hosts.yml`, `.azure`, `.config/gcloud`, `.terraform.d/credentials.tfrc.json`, CryptoAPI RSA/DSS keys (`AppData\Roaming\Microsoft\Crypto`), DPAPI master keys + CREDHIST (`AppData\Roaming\Microsoft\Protect`), Win Credential Manager, Chrome / Edge / Firefox cookie stores). Everything else stays under the user's natural NTFS permissions — `C:\Users\<self>\*` is RW, `C:\Windows` / `C:\Program Files\*` / `C:\ProgramData\*` are RO, `C:\Users\<other>\*` is denied by Windows' own NTFS ACE for the other user's SID. `host_path == guest_path` — no path translation. |
| Network | Profile-declared (`open` / `allowlist` / `blocked`). A non-empty Windows `allowlist` is enforced by a user-mode WFP filter set (app-id-scoped block + per-IP permit), brokered through the elevated dizgind daemon. This is accidental-egress protection, not hostile-tool grade (a same-SID process can delete the filters); a kernel-mode callout driver is on the roadmap. `DIZGIN_NO_WFP=1` reverts to advisory. |
| Process | Job Object — `KILL_ON_JOB_CLOSE` + memory cap (`JOB_OBJECT_LIMIT_PROCESS_MEMORY`) + PID cap (`JOB_OBJECT_LIMIT_ACTIVE_PROCESS`) + UI restrictions (handles / clipboard / system params / display / global atoms / desktop / `ExitWindows`). |
| Token | Restricted token via `CreateRestrictedToken DISABLE_MAX_PRIVILEGE` + integrity label lowered to **Medium** (`S-1-16-8192`). Privilege ladder is empty (`DISABLE_MAX_PRIVILEGE` strips every privilege except `SeChangeNotifyPrivilege` so NTFS traversal stays alive). No `SidsToDisable` or `RestrictedSids` are passed — the user SID continues to identify the process for NTFS, which is the whole point of the iter6 model. |
| Process mitigations | Per-child `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` PTAL: DEP **ON**, ASLR (ForceRelocate + HighEntropy + BottomUp) **ON**, ImageLoad NoRemote + NoLowMandatoryLabel + PreferSystem32 **ON**, StrictHandleChecks **ON**, ACG (ProhibitDynamicCode) **OFF** — see CLAUDE-HANG-01 note below. `BlockNonMicrosoftBinaries` is **opt-in only** via the `compatibility.mitigation_policy` YAML field (default OFF because it breaks any tool that loads a third-party DLL). |

The sandbox runs as a regular Windows process under a restricted, Medium-IL token spawned via `CreateProcessAsUserW`. There is no AppContainer profile, no per-session AC SID, and no capability set. The defense-in-depth surface that matters is the DACL DENY on the sensitive SSOT (one entry per credential path, applied in-process via `SetNamedSecurityInfo` and revoked on session exit by walking the tree with `SET_ACCESS` — see the REVOKE_ACCESS asymmetry note in [Enforcement](#enforcement)).

**Defense Layer (kernel boundary)** — kernel is shared with the host (the same Edge / Chrome renderer trade-off). The restricted token + Medium IL + Job UI restrictions + per-child mitigation set + DACL DENYs combine to the production model for an unprivileged userland sandbox. DIZGIN does not claim hypervisor-grade isolation here.

#### Why ACG is OFF — CLAUDE-HANG-01 (iter5 root cause, iter6 closed)

The iter5 AppContainer backend implicitly enabled ACG (Arbitrary Code Guard / `PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON`) because the AppContainer profile pipeline turned it on by default. Bun ships an in-process JavaScriptCore JIT — exactly the pattern ACG was designed to stop. The first JIT page allocation under ACG returns `STATUS_DYNAMIC_CODE_BLOCKED` and the Bun runtime wedges silently. CLAUDE-HANG-01 was the visible symptom: `dizgin -- claude --version` hung because Claude Code is a Bun SEA.

iter6 fixes the issue structurally: the restricted backend's `DefaultPolicies()` (`internal/sandbox/restricted/mitigation_windows.go`) explicitly leaves the ACG bit clear. Bun, Node experimental JIT users, .NET Core, Electron — any runtime with an in-process JIT — loads cleanly. Tools that want the extra hardening can opt in via `compatibility.mitigation_policy.allow_dynamic_code: false` (today a reserved YAML field; the wiring lands when the use case justifies the breakage).

#### Red Line Verification — Windows (iter6 model)

iter6 inverted the iter5 model: instead of declaring an **allowlist** of permitted paths and DENY-by-default everywhere else (the AppContainer SID model), iter6 declares a small **DENY-list** of high-value credential surfaces and lets the user's natural NTFS permissions cover everything else. The trade-off is documented under [Defense Layer Composition](#defense-layer-composition); the practical R1 view is:

| Tier | What | Enforcement | Failure mode | Evidence |
|------|------|-------------|--------------|----------|
| R1-DENY (sensitive) | Hardcoded SSOT of credential paths: `.ssh`, `.aws/credentials`, `.aws/config`, `.gnupg`, `.netrc`, `.docker/config.json`, `.kube`, `.git-credentials`, `.config/gh/hosts.yml`, `.azure`, `.config/gcloud`, `.terraform.d/credentials.tfrc.json`, DPAPI vault (`AppData/Roaming/Microsoft/Crypto`), Win Credential Manager (`AppData/Local/Microsoft/Credentials`), Win Vault, Chrome / Edge / Firefox cookie stores. | DACL DENY ACE for the user SID with OI+CI inheritance, applied via `SetNamedSecurityInfo` at session start. Revoked at exit by walking the tree with `SET_ACCESS` (zero perms) so both DENY and any prior GRANT entries are stripped — the documented `SetEntriesInAcl REVOKE_ACCESS` asymmetry would otherwise leave the DENY in place. | Session refuses to start (fail-closed). A partial DENY application rolls back every successful stamp + removes the scratch dir + surfaces a typed error. | `internal/security/sensitive_paths_windows.go::SensitiveDenyPaths`, `internal/sandbox/restricted/acl_windows.go::StampPathDeny / StampPathGrant`, `internal/sandbox/restricted/backend.go::Create` |
| R1-USER | `C:\Users\<self>\*` minus the DENY set. | The restricted token runs as the same user as dizgin; NTFS already grants the user's own SID `Full Control` on the user profile tree, so no explicit GRANT is needed. | N/A — covered by Windows' default user-profile ACL. | NTFS — installation-defined. |
| R1-SYSTEM | `C:\Windows`, `C:\Program Files\*`, `C:\ProgramData\*`. | RO under the user's natural NTFS rights; admin-only writes hard-fail. | N/A — Windows enforces directly. | NTFS — installation-defined. |
| R1-OTHER-USERS | `C:\Users\<other>\*`. | Denied by Windows' own NTFS ACE for the other user's SID. dizgin adds nothing on top. | N/A — kernel hard-deny. | NTFS — installation-defined. |
| R1-TEMP (iter5 L1, kept) | Per-session `TEMP` / `TMP` / `TMPDIR` redirected to a scratch dir under `%LOCALAPPDATA%\dizgin\restricted\<sid>\`. | Self-extracting runtimes (Bun SEA, Node electron bundles) write into the sandbox-private scratch instead of the host's `%TEMP%`. Emergency switch: `DIZGIN_NO_TEMP_OVERRIDE=1`. | Bun extract fails into the parent's `%TEMP%` — tool falls back to a working state, no security regression. | `cmd/dizgin/env.go::buildToolEnv`, `internal/sandbox/restricted/scratch_windows.go` |
| R1-HANDLES (iter5 L2, kept) | `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` registered on the PTAL with exactly the three stdio handles; `bInheritHandles=TRUE` is scoped to that list. | Ambient inheritable handles in dizgin's process table do not reach the child. Emergency switch: `DIZGIN_NO_HANDLE_LIST=1`. | Renderer-spawn pattern matching Edge / Chrome / fastrender. | `internal/sandbox/restricted/box_windows.go::Start` (PTAL setup), `handle_list_windows.go::applyHandleListAllowlist` |
| R2 — Native | Tool runs as a real Win32 process under the same user identity with anonymous-pipe stdio (SD grants the user SID `GENERIC_ALL`), full `\\.\pipe\dizgind` access, native `cmd.exe` / `bash.exe` / `git.exe`. MSYS2 `getcwd()` resolves through the user-profile chain because the restricted token preserves `SeChangeNotifyPrivilege` (bypass-traversal) — no admin-once volume-root grant is required. No shim, no path remap, no UVM boot. | `host_path == guest_path` throughout. | `internal/sandbox/restricted/box_windows.go::Start`, `stdio_windows.go::newStdio`, `tests/e2e/msys2_getcwd_windows_test.go` |

**Audit logging.** Every classifier decision is appended to `~/.dizgin/audit/<session-id>.jsonl` via `internal/audit/mount.go::LogMountDecision`. A post-mortem is a single `jq` invocation over the session file — category, host path, read-only flag, granted boolean, and any wrapped error all live on one record.

**Fail-closed with actionable hint.** Partial DENY application aborts session creation under R1: a half-stamped tree (some sensitive paths protected, others not) is worse than no tree, so a single stamp failure rolls back every successful stamp + removes the scratch dir + surfaces a typed error. The dizgin process never falls back to a "best-effort" partial DENY.

#### Defense Layer Composition

The iter6 backend trades AppContainer's capability isolation for a model that keeps Bun-class JIT runtimes working. The four layers that remain:

1. **Restricted token + Medium IL** — privilege drop + label drop. `OpenProcess` against the parent succeeds (same user, same IL), but the privileges that would let the child mutate kernel-protected objects (`SeDebugPrivilege`, `SeTcbPrivilege`, `SeLoadDriverPrivilege`, …) are stripped.
2. **Per-child mitigation policy bitfield** — DEP / ASLR / Image Load hardening / Strict Handle Check applied via PTAL so the kernel enforces them from image-load time. ACG and `BlockNonMicrosoftBinaries` stay off by default for Bun-compat / dev-tool-compat reasons documented above.
3. **Job Object** — kill-on-close, memory cap, PID cap, UI restrictions. The child cannot enumerate the parent desktop, send window messages to other processes, or escape via `ExitWindowsEx`.
4. **DACL DENY on the sensitive SSOT** — the only credential paths the AI tool could plausibly want are the ones we lock down per session. Browser cookies, SSH keys, cloud credentials, GitHub token store, CryptoAPI RSA store, DPAPI master keys + CREDHIST — sixteen entries today, all reviewed in `internal/security/sensitive_paths_windows.go`.

**What we lost vs iter5 AppContainer:** R7 (kernel boundary) drops from `kernel-shared/capability-restricted` to `kernel-shared/restricted-token`. The kernel attack surface is broader — instead of a capability-gated subset of syscalls, the restricted process can call the full Win32 API and is constrained only by its (empty) privilege ladder + integrity level. This is the trade we accepted to unblock Bun-class runtimes; the WFP kernel allowlist (network) and a future ETW-based audit are tracked on `docs/ROADMAP.md` as the path back to a tighter posture without re-introducing ACG.

**What we kept from iter5:** the per-session TEMP redirect (L1), the handle-list allowlist (L2), the per-profile `compatibility:` toggles, and the no-fallback policy. None of those touched the AppContainer SID or capability set, so the iter6 reset preserved them unchanged.

#### Enforcement

- **FS** — DACL DENY ACEs on the sensitive SSOT, applied in-process via `SetNamedSecurityInfo`. `Box.Cleanup` revokes by walking the tree with `SET_ACCESS` (zero perms) instead of `REVOKE_ACCESS`, because the documented `SetEntriesInAcl` `REVOKE_ACCESS` asymmetry only strips `ACCESS_ALLOWED` ACEs — it would leave a stamped `ACCESS_DENIED` ACE in place. The tree walk also handles Windows' `INHERITED_ACE` propagation rules (additions auto-propagate, removals do not).
- **Volume root traversal** — none. iter6's restricted token leaves `SeChangeNotifyPrivilege` enabled (`CreateRestrictedToken` is called with `SidsToDisable=0` and `RestrictedSids=0`, see `token_windows.go`), so NTFS bypass-traversal works under the user's natural ACL. iter7 removed `dizgind setup` entirely; no admin-once host-side ACE is required for MSYS2 / Cygwin tools.
- **Network** — `open` / `allowlist` / `blocked` are profile-declared. A non-empty Windows `allowlist` is enforced by a **user-mode WFP** filter set (`internal/netfilter`): an app-id-scoped catch-all block at `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` plus a higher-weight permit per resolved IP, all added inside one transaction in a *dynamic* WFP session. dizgin is non-elevated and cannot hold `FWPM_ACTRL_ADD`, so the filter add is brokered through the elevated dizgind daemon (`wfp_apply` / `wfp_revoke` IPC). On revoke — or on daemon/dizgin death — the dynamic session's engine handle closes and BFE auto-reaps every filter, so there is no leak path. **Honest boundary:** a process under the same user SID can enumerate and delete these filters (`FwpmFilterDeleteById0`), so this is *accidental-egress* protection (a tool reaching the wrong CDN, a stray `curl` in a test), **not** a defense against a hostile tool that tears down its own enforcement. The hostile-grade path is a kernel-mode WFP callout driver, tracked as ROADMAP #1. `DIZGIN_NO_WFP=1` reverts to advisory; CIDR ranges are unsupported in the interim (logged, never silently dropped).
- **Resources** — Job Object (`JOB_OBJECT_LIMIT_PROCESS_MEMORY` / `_ACTIVE_PROCESS`), Linux cgroups, macOS rlimit (`RLIMIT_NPROC` for `max_pids` only — Darwin's kernel rejects a finite `RLIMIT_AS`, so `memory_mb` is not enforced on macOS). Default `resources.timeout=30m` caps runaway loops.
- **Privileges** — `security.no_new_privileges` / `drop_all_caps` are Linux-only (`--unshare-user` yields `cap=0` in the new namespace); Windows + macOS no-op (kept for cross-platform YAML portability).
- **Credentials** — SSH agent socket forwarded (key never enters sandbox), API keys via `0600` temp env injection, multi-source GitHub token resolution.
- **IPC** — anonymous pipe SDs grant the user SID `GENERIC_ALL` (simpler than the iter5 acStdio that needed an AC SID + user SID); pipe handles inherited via `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` PTAL so only the three stdio handles cross the parent/child boundary.

### macOS — Seatbelt (`sandbox-exec`)

| Property | Guarantee |
|----------|-----------|
| Filesystem | Broad base reads (`/usr`, `/System`, `/Library`, `/private/etc`) plus blanket `/tmp` read+write, profile-declared mounts get their own R/W or R/O grant, and everything else is denied by the base `(deny default)`. An R1 DENY overlay then blocks the sensitive-credential SSOT (`.ssh`, `.aws/credentials`, `.gnupg`, DPAPI-equivalent keychains, browser cookie stores, …) on top of all of the above — SBPL is last-match-wins, so the deny rule always overrides a broader earlier allow, including the blanket `/tmp` and base-read grants. **Known limitation:** unlike Linux bwrap, Seatbelt has no mount-namespace equivalent to give each session an isolated `/tmp` — any two sandboxed sessions (or a sandboxed session and an unrelated host process) share the same real `/tmp`. Accepted trade-off: scoping `/tmp` down risks breaking real tools that rely on shared `/tmp` locations (editors, IPC sockets, Homebrew). |
| Network | Per-IP allowlist: each allowed hostname is resolved to its current A/AAAA records at session start and one SBPL permit rule is emitted per resolved IP (SBPL only matches on IP literals, not hostnames). DNS (UDP/TCP `:53`) and loopback stay open so name resolution keeps working. CIDR entries and unresolvable hosts fail closed (session refuses to start) rather than shipping a partial policy. `blocked` denies all network via the base default-deny; `open` allows everything. |
| Process | `process-exec` + `process-fork` allowed; subprocess containment is enforced via the filesystem + network rules above (they apply transitively to fork descendants). AI coding tools spawn many subprocesses (git, npm, language servers, build tools) — denying fork would break R2 (Native Experience). |

Seatbelt is a kernel-enforced MAC policy. Bypass requires a kernel exploit; userland code that crosses the policy boundary is denied even when running under root.

### Linux — bubblewrap

| Property | Guarantee |
|----------|-----------|
| Filesystem | Bind mounts only — unreachable host paths are invisible to sandbox. R1 cover-mounts (empty 0000 tmpfs / files) shadow any sensitive-SSOT path that falls under a declared mount. |
| Namespaces | New user, mount, PID, IPC, UTS namespaces (`--unshare-user` yields `cap=0` inside). |
| Network | `blocked` → `--unshare-net` (isolated, loopback-only); `open` → `--share-net` (full host network). **`allowlist` is not yet enforced and is rejected outright**: `bubblewrap.Create()` returns an error rather than silently downgrading to `blocked` (which would also block the intended hosts) or `open` (which would grant everything). A `--unshare-net` namespace has only loopback, so no in-namespace nftables ruleset can reach an allowed host regardless of capability — real per-host egress needs a veth+NAT pair or a userland proxy (pasta/slirp4netns), tracked as ROADMAP #1's Linux counterpart and requiring a Linux dev host to build and verify. |
| Syscalls | seccomp-BPF deny-list: 20+ dangerous syscalls blocked (ptrace, mount, setuid, bpf, etc.). |

**Sessions that request `network.policy: allowlist` on Linux fail at `Create()`** with an error pointing to `blocked` (strict denial) or `open` (unrestricted) as the only currently-enforced policies.

---

## Credential Handling

### SSH Agent Forwarding

The SSH agent socket is bind-mounted into the sandbox. The private key **never enters the sandbox** — the sandbox can only sign challenges via the socket. If the sandbox is compromised, only signatures (not keys) are exposed.

### API Key Injection

API keys are injected as environment variables at process creation. They are never written to disk inside the sandbox. Memory scanning by a compromised sandbox process is a residual risk; `zero_residue: true` mode clears tmp files on exit but cannot clear env memory.

### GitHub Token

Resolution order:
1. `GITHUB_TOKEN` env var (host)
2. `GH_TOKEN` env var (host)
3. `gh` CLI config file
4. Git credential store

The resolved token is injected as `GITHUB_TOKEN` inside the sandbox.

### Git Identity

Git name/email are read from `git config` and injected as `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`, `GIT_COMMITTER_NAME`, `GIT_COMMITTER_EMAIL`. No credentials are injected, only identity.

---

## Known Limitations

| Platform | Limitation |
|----------|-----------|
| Windows | Restricted token requires Windows 8 or newer (Process Mitigation Policy API). No UAC, no Hyper-V, no Containers feature required. |
| Windows | DACL DENY on the user SID also blocks the user's *other* processes (ssh-agent, git push from another terminal, …) for the duration of the dizgin session — for paths in the sensitive SSOT only. Cleanup reliably revokes; the audit log records every applied DENY so an orphan sweeper can recover if dizgin crashes mid-session. Per-tool overrides at `~/.dizgin/permissions/<tool>.yaml` (iter6 Phase D) let the user exempt specific sensitive paths for a specific tool. |
| All userland sandboxes | Kernel is shared with the host. The restricted backend (Windows), Seatbelt (macOS), and bwrap (Linux) all run inside the host kernel. The defense stack — restricted token + Medium IL + Job + mitigation bitfield (Win), kernel-MAC (macOS), user namespace + seccomp (Linux) — matches the production model used by Edge / Chrome / Firefox renderers at scale. DIZGIN does not claim hypervisor-grade isolation. shimV2 (Microsoft, tracked Q3-Q4 2026) will restore kernel isolation on Windows when ready. |
| Windows | Network allowlist enforcement is user-mode WFP (brokered through the elevated daemon), which a same-SID process can tear down — it stops accidental egress, not a hostile tool. A kernel-mode WFP callout driver (ROADMAP #1) is the hostile-grade path. Interim hardening: pair with a host firewall rule for defense in depth. |
| Linux | Network allowlist is not yet enforced at all — `network.policy: allowlist` fails at `Create()` regardless of capability (a `--unshare-net` namespace has only loopback, so no in-namespace nft ruleset could reach an allowed host). Use `blocked` or `open` today; filtered egress needs a veth/NAT or userland-proxy layer, tracked as ROADMAP #1. |
| All | Memory inside sandbox process is accessible to the sandbox; env vars can be read by the running tool. |

---

## Threat Model

**In scope (protected):**
- Credential-shaped paths under the user profile (SSH/PGP/AWS/k8s/Docker/GitHub keys + Windows DPAPI vault + browser cookies)
- Other users' data (NTFS / POSIX enforced)
- System directories (read-only via natural permissions; admin-required writes hard-fail)
- Host process list (privilege drop denies `OpenProcess` for `SeDebugPrivilege`-gated operations)
- Files the user has not explicitly authorised for the tool via `~/.dizgin/permissions/<tool>.yaml`

**Out of scope (not protected):**
- A compromised tool that exfiltrates injected env vars (API keys, tokens)
- Side-channel attacks (CPU cache timing, Rowhammer, Spectre/Meltdown class)
- Kernel exploits targeting the sandbox mechanism itself
- Hardware attacks (DMA, USB physical access, malicious peripherals)
- Ring-0 malware already on the host (rootkits, signed-kernel-driver attacks)
- Pre-existing host compromise (dizgin trusts the OS it runs on)
- Data the sandbox is explicitly granted access to (by design)
- Supply chain attacks against Go modules / Windows SDK headers — mitigated by SLSA L3 attestation on releases (planned, item B1)
- Network-layer MITM where the user has installed a malicious root CA on the host

---

### STRIDE Analysis — Trust Boundaries

The two trust boundaries dizgin crosses every session are (1) the dizgind daemon IPC and (2) the per-session file write surface (DACL DENY stamps + scratch dir). The matrix below names the threat per STRIDE category and the mitigation, so a security review can audit each surface against the same template.

#### Surface 1: dizgin ↔ dizgind IPC (`\\.\pipe\dizgind` / unix socket)

| STRIDE | Threat | Mitigation |
|--------|--------|------------|
| Spoofing | A non-dizgin process impersonates dizgin and asks dizgind to perform a privileged setup operation | Pipe DACL grants only the user SID and LocalSystem. Unix builds use `SO_PEERCRED` to verify the client UID matches the dizgind owner. |
| Tampering | An on-host attacker rewrites IPC messages in flight | The IPC channel is OS-local (named pipe / unix socket) — no network surface, no MITM path. Tampering requires already-elevated host access, which is out of scope. |
| Repudiation | dizgin denies sending a request that dizgind fulfilled | Every IPC verb hits the audit logger (`internal/audit`) with timestamp + caller PID + verb + payload. JSON-L lines are append-only; rotation is size-based. (Tamper-evident HMAC chain is a Phase 2 item, B5.) |
| Information disclosure | Dizgind leaks session state to an unauthorised reader | Pipe DACL grants only the user SID + LocalSystem. No persistent state files on the filesystem post-iter7 (the setup marker was removed). |
| Denial of service | A malicious client floods dizgind with requests | Dizgind's RPC handler is bounded; excess requests block on the channel rather than fork unbounded. iter3 retired the per-session `stamp_paths` / `revoke_sid` RPCs (the only high-volume verbs); the surface that remains is `register` / `heartbeat` / `deregister` / `command`, each idempotent and rate-limited by the natural lifecycle frequency. |
| Elevation of privilege | Dizgind, running elevated, performs a destructive operation | iter7 removed `dizgind setup` entirely (the only command that mutated host-side ACLs). dizgind's only elevated work today is binding the named pipe with a SYSTEM security descriptor at daemon start; there is no RPC verb that can drive dizgind to mutate ACLs on demand. |

#### Surface 2: DACL DENY stamping + scratch dir (dizgin's own writes)

| STRIDE | Threat | Mitigation |
|--------|--------|------------|
| Spoofing | A path is stamped under the wrong trustee, locking out a different process | The trustee is always the current user SID resolved via `OpenProcessToken(GetCurrentProcess())`; no name-to-SID lookup race, no foreign SID input. |
| Tampering | An attacker overwrites a sensitive path's pre-existing ACL between DENY application and dizgin's exit | DACL DENY writes use `SetNamedSecurityInfo` with `DACL_SECURITY_INFORMATION`; the cleanup tree-walk reads back with `GetNamedSecurityInfo` and re-stamps via `SET_ACCESS` (zero perms) to ensure both the DENY and any third-party-added ACE for the user SID are removed. Concurrent third-party modifications race with the cleanup; the audit log records every applied DENY so a recovery script can rebuild. |
| Repudiation | dizgin denies stamping a path that turned out to leak | Every successful DENY stamp + every revoke is logged at `log.Verbose("restricted", ...)`. Failed stamps abort `Box.Create()` and surface a typed error to the user. |
| Information disclosure | The DACL probe (`GetNamedSecurityInfo`) exposes the existing ACE list to a future attacker reading audit logs | Audit log entries store the path and result, not the full DACL dump. Verbose mode (`DIZGIN_DEBUG=1`) prints the user SID in stderr but not the full DACL. |
| Denial of service | A user supplies a profile with thousands of mount entries | The sensitive SSOT is hardcoded (19 entries today); user mounts go through a different code path that does not stamp DACLs. The per-tool `~/.dizgin/permissions/<tool>.yaml` override file is human-edited; flooding requires a manual edit of the YAML, which is out of scope. |
| Elevation of privilege | A DENY stamp is misapplied and locks the user out of their own profile permanently | `Box.Cleanup` runs on every exit path with a 3 s wall-clock deadline; the audit log records every applied DENY so a manual recovery (`icacls /reset` on the listed paths) is always possible. A panic between stamp and cleanup would still leave the DENY in place — accepted MVP risk; mitigations under consideration include a daemon-side cleanup pass at startup. |

---

## Red Line Verification

The two red lines (R1 Sensitive Surface Isolation, R2 Native Experience) are validated through a mix of unit tests, integration tests, and live artifacts. Evidence summary:

### R1 — Sensitive Surface Isolation

| Evidence | Where |
|----------|-------|
| User SID is denied access to every sensitive SSOT path that exists on disk | `internal/sandbox/restricted/backend.go::Create` + `acl_windows.go::StampPathDeny` |
| DENY ACEs are reaped on `Box.Cleanup` via `SET_ACCESS` tree-walk (covers the `SetEntriesInAcl REVOKE_ACCESS` asymmetry) | `internal/sandbox/restricted/box_windows.go::Cleanup` + `acl_windows.go::StampPathGrant` (revoke form) |
| Sensitive SSOT is a hardcoded list — no profile-driven path can shrink it (only the per-tool permission file can exempt a single path for a single tool) | `internal/security/sensitive_paths_windows.go::sensitiveRelativePaths` (SSOT) |
| `host_path == guest_path` — no parent-dir mount can leak the host profile, since the SSOT entries land on the same path the tool would reference | `internal/sandbox/restricted/backend.go::Create` |
| E2E acceptance: `dizgin -- cmd //c "type %USERPROFILE%\.ssh\known_hosts"` returns "Erişim engellendi." | `tests/e2e/r1_fail_closed_after_setup_windows_test.go` |

### R2 — Native Experience

| Evidence | Where |
|----------|-------|
| Tool runs as a real Win32 process with the user's identity and anonymous-pipe stdio | `internal/sandbox/restricted/box_windows.go::Start` |
| File edits land on the host path directly (no staging layer, no SyncBack) | `host_path == guest_path` — `internal/sandbox/restricted/backend.go::Create` |
| Bash subprocess works against host Git for Windows under the dizgind-setup volume traversal grant | `tests/e2e/setup_then_gitops_windows_test.go` |
| Parallel dizgin sessions use distinct scratch dirs (`dizgin-dizgin-<pid>-<nano>`) | `internal/sandbox/restricted/backend.go::Create` (scratch naming) |
| Stdio survives the spawn — no Low-IL kernel drop, no AC-SID grant required | `tests/e2e/no_pty_stdio_windows_test.go` |

### No-Fallback Policy

| Evidence | Where |
|----------|-------|
| Linux bwrap `network.policy: allowlist` (not yet enforced) → `Create()` returns error (no silent open-network fallback) | `internal/sandbox/bubblewrap/backend.go::Create` |
| Windows restricted backend cannot resolve user SID → `Create()` returns error (no degraded mode) | `internal/sandbox/restricted/backend.go::Create` |
| Partial sensitive-DENY application → roll back successful stamps + remove scratch dir + return error (no half-protected session) | `internal/sandbox/restricted/backend.go::Create` (rollback path) |
| No `--disable-sandbox` flag, no insecure fallback path: `git grep -n "disable.?sandbox\|bypass" cmd/ internal/` yields zero matches | repo-wide |
| Orphan scratch dir collector runs on daemon startup + hourly | `internal/daemon/staging_cleanup_windows.go` |

---

## Permission Learning (iter6 Phase D)

The DACL DENY model has a known tension: if a tool legitimately needs one of the sensitive SSOT paths (e.g. a tool whose purpose is to audit `~/.ssh/known_hosts`), the default DENY blocks it. iter6 Phase D adds an opt-in escape valve.

### Flow

1. User runs `dizgin --learn -- <tool>`. The DENY stamps stay in place, but dizgin wraps the child's stderr with an access-denial recorder that scans for locale-aware denial keywords (`access denied` / `permission denied` / `operation not permitted` / Turkish `engellendi` / German `verweigert` / Spanish `denegado`).
2. On exit, dizgin prints a summary of captured denial lines. Each line is run through path-extraction regex patterns; the deduplicated absolute paths feed an interactive prompt.
3. For each path the user chooses:
    - **rw** — full read-write exemption. Path will be skipped from the DENY sweep on the next run.
    - **ro** — read-only exemption (a future revision may apply a real read-only shim; today the path is treated identically to rw at the DACL layer).
    - **deny** — keep the DENY; remember the decision so the path is not re-prompted next session.
    - **skip** — record nothing; the path will be re-prompted on the next `--learn` run.
4. Decisions are written atomically to `~/.dizgin/permissions/<tool>.yaml` via a temp-file + `os.Rename` (Windows `MoveFileEx MOVEFILE_REPLACE_EXISTING` — atomic).
5. The next normal run (no `--learn`) auto-loads the file and the listed paths are exempted from the sensitive-SSOT DENY pass.

### Schema

```yaml
version: 1
tool_name: claude
tool_path: C:\Users\me\AppData\Local\Programs\Claude\claude.exe
learned_at: 2026-05-18T10:30:00Z

overrides:
  rw: []                                 # full RW exemption
  ro:                                    # RO exemption
    - 'C:\Users\me\.aws\credentials'
  deny:                                  # explicit DENY (tool-specific, even if not in SSOT)
    - 'C:\Users\me\projects\private-keys'
```

### Safety considerations

- **Auto-load default ON.** The user opted in once; re-running `dizgin -- <tool>` should not require re-confirmation. Re-enter the prompt loop with `dizgin --learn`.
- **TTY detection.** Non-TTY stdin (CI, scripts, piped input) auto-defaults every entry to `skip`. The prompt loop cannot hang an unattended job.
- **High-risk path warning.** When the prompt offers a credential-shaped path (anything matching `.ssh`, `.aws/credentials`, `.gnupg`, DPAPI vault, browser cookies, …) it prints an extra `[!] this path holds credential material` warning before reading the choice.
- **Tool-path mismatch warning.** The profile records the tool's absolute path at the time the decision was made. If the binary later moves (e.g. after a reinstall), the next normal run prints a warning so the user can re-confirm the saved decisions.
- **Atomic write.** Temp file + `os.Rename` (atomic on Windows via `MoveFileEx MOVEFILE_REPLACE_EXISTING`); concurrent writes from two dizgin sessions for the same tool race to last-write-wins, which is acceptable because the decisions are human-driven and rare.
- **Reset by deletion.** `rm ~/.dizgin/permissions/<tool>.yaml` reverts the tool to the SSOT default. There is no `dizgin permissions reset` subcommand today (tracked: iter6 follow-up).

---

## Reporting a Vulnerability

Open a **private** GitHub Security Advisory:
`https://github.com/sungurerdim/dizgin/security/advisories/new`

Include: affected version, OS/backend, reproduction steps, impact assessment.

Do not open a public issue for security vulnerabilities.

### Disclosure Timeline

- **48 hours**: Initial acknowledgement of report
- **7 days**: Preliminary assessment and severity classification
- **90 days**: Fix development and coordinated disclosure deadline
- **Patch release**: Published with CVE (if applicable) and security advisory
