# DIZGIN Windows Sandbox — ds-solve Brief

> **Status (2026-05-03):** historical brief — documents the iteration history that led to the production Windows sandbox. The approaches below were tried and abandoned on the way to the current model (iter6, 2026-05-18): `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` + Medium IL (`S-1-16-8192`) + Job Object + DACL DENY ACEs on a 19-path sensitive SSOT. AppContainer/LowBox was an intermediate stop that was itself retired due to ACG/JIT incompatibility (CLAUDE-HANG-01). For the current design see `docs/SECURITY.md`.

## Problem

Running AI tools (Claude Code, Copilot, Cursor, etc.) in a filesystem-isolated sandbox on Windows. Two red lines:

1. **Full FS Isolation** — tool can only access declared paths, nothing else
2. **Native Experience** — tool must not notice it's sandboxed (named pipes, TUI, REPL must work)

Containers provide kernel-level isolation but block named pipe creation — pipe-IPC tools like Claude Code hang. Restricted token via `CreateProcessAsUser` requires `SeIncreaseQuotaPrivilege`, which normal users don't have.

## Tried and Failed Approaches

### 1. CreateProcessWithTokenW (restricted token)
- **Result:** `ERROR_PRIVILEGE_NOT_HELD`
- **Cause:** `SeImpersonatePrivilege` required, not available to normal users
- **File (historical):** `internal/sandbox/appcontainer/restricted.go` (package deleted in iter6)

### 2. CreateProcessAsUser (restricted token, normal user)
- **Result:** `ERROR_PRIVILEGE_NOT_HELD` (1314)
- **Cause:** `SeIncreaseQuotaPrivilege` required, not available to normal users
- **Note:** MSDN says "no privilege required for restricted version of caller's own token" but in practice it's required

### 3. NtSetInformationProcess(ProcessAccessToken)
- **Result:** `STATUS_PRIVILEGE_NOT_HELD` (0xc0000061)
- **Cause:** `SeAssignPrimaryTokenPrivilege` required, kernel-level requirement

### 4. Self-restrict parent → CreateProcess
- **Result:** After `AdjustTokenPrivileges(DisableAll)`, even `CreateProcess` fails
- **Cause:** Stripping own privileges prevents process creation entirely

### 5. CreateProcess(SUSPENDED) → self-restrict parent → resume child
- **Result:** Child runs with FULL TOKEN (Medium IL, all privileges)
- **Cause:** Token is a creation-time snapshot — child was created before parent was restricted
- **Evidence:** `whoami /priv` shows all privileges, Desktop/Documents readable and writable

### 6. dizgind admin broker (impersonated user token)
- **Result:** `CreateProcessAsUser: ERROR_PRIVILEGE_NOT_HELD`
- **Cause:** Broker uses `ImpersonateNamedPipeClient` to get user token, creates restricted token from it. Since the token isn't the caller's "own" token, privileges aren't auto-enabled

### 7. dizgind admin broker (admin's own token)
- **Result:** `CreateProcessAsUser: ERROR_PRIVILEGE_NOT_HELD`
- **Cause:** `LaunchRestrictedProcess` duplicates its own process token and creates a restricted token, but `CreateProcessAsUser` still fails. `enablePrivilege("SeIncreaseQuotaPrivilege")` is called but admin token shows this privilege as "Disabled" and `AdjustTokenPrivileges` may appear successful without actually enabling it.

### 8. dizgind admin broker + CreateProcessWithTokenW
- **Result:** Process is created (no error) but stdio doesn't reach the child
- **Cause:** `CreateProcessWithTokenW` has no `bInheritHandles` parameter — anonymous pipe handles aren't inherited by the child. Stdio goes to admin console.

## Untried Alternatives

### ALT-A: Chromium two-phase wrapper (MOST PROMISING)
- dizgin launches itself as child: `CreateProcess("dizgin --restricted-exec tool args")`
- Child dizgin:
  1. Self-restrict token: `AdjustTokenPrivileges(DisableAll)` + `SetTokenInformation(Low IL)`
  2. `CreateProcess("tool", args)` to launch tool — child tool inherits restrictions
- **Research finding:** Child inherits parent's current token state. So after child dizgin restricts its token, the tool process it creates also gets the restricted token.
- **Risk:** In attempt #4, `AdjustTokenPrivileges` followed by `CreateProcess` failed. But that attempt called `CreateProcess` immediately — perhaps the issue was `STARTF_USESTDHANDLES` handle access. Opening handles first then restricting might work.
- **Files:** `cmd/dizgin/main.go` (new `--restricted-exec` flag), `cmd/dizgin/restricted_exec_windows.go` (new)

### ALT-B: CreateProcessWithTokenW + named pipe stdio
- Attempt #8 succeeded (process created) but stdio didn't work
- **Solution:** Use named pipes instead of anonymous pipes — child opens pipe by name (no inheritance needed)
- **How:** Broker creates 3 named pipes (`\\.\pipe\dizgin-<pid>-stdin/stdout/stderr`), passes pipe names to child via env vars, child opens them
- **Issue:** Tools (claude, node) don't automatically read stdin/stdout from pipes — must be set via STARTUPINFO. Named pipe handles can be opened via `CreateFile` and set in STARTUPINFO, but `CreateProcessWithTokenW` doesn't support handle inheritance.
- **Possible fix:** DLL injection or wrapper script for pipe redirect at child startup? Complex.

### ALT-C: Debug SeIncreaseQuotaPrivilege in admin process
- In attempt #7, admin token shows `SeIncreaseQuotaPrivilege` as "Disabled"
- `enablePrivilege` function calls `AdjustTokenPrivileges` and returns no error
- **Hypothesis:** `AdjustTokenPrivileges` returns success but privilege isn't actually enabled (ERROR_NOT_ALL_ASSIGNED check may not work properly)
- **Test:** Run `whoami /priv` in admin PowerShell to see SeIncreaseQuotaPrivilege state, then manually enable and test `CreateProcessAsUser`
- **File (at time of brief):** `internal/sandbox/appcontainer/restricted.go` → `enablePrivilege` function (package since deleted)

### ALT-D: CreateProcess + Job Object only (no FS isolation, resource limits only)
- Doesn't meet Red Line #1 but it works
- Current fallback path — but identified as insecure
- **Last resort only**, with explicit user warning

### ALT-E: dizgind as Windows Service
- Run as Windows Service instead of admin broker (SYSTEM token)
- SYSTEM token has `SeAssignPrimaryTokenPrivilege` + `SeIncreaseQuotaPrivilege` + `SeImpersonatePrivilege`
- `CreateProcessAsUser` as a service definitely works
- **Extra work:** Service installer, service management, creating process in interactive session (Session 0 isolation)
- Most robust but most complex path

### ALT-F: setup-security to grant SeIncreaseQuotaPrivilege + re-login
- Previous approach: grant privilege to user via `LsaAddAccountRights`
- Found to not work even after PC restart (previously tested)
- **Hypothesis:** Grant was applied (visible in secedit export) but Windows didn't load it into token on re-login
- **Test:** Open `secpol.msc` in admin PowerShell for manual verification

## Code State at Time of Brief (2026-05-03 — historical)

> The files below were the state during the search phase. Most no longer exist.
> The production implementation lives in `internal/sandbox/restricted/`.

- `internal/sandbox/appcontainer/restricted.go` → `LaunchRestrictedProcess` (broker approach, later retired)
- `internal/daemon/broker_windows.go` → Broker IPC handler (impersonate + launch, later retired)
- `internal/daemon/codec.go` → `TypeLaunchSandboxed` + JSON stdio framing (later retired)
- `cmd/dizgin/job_windows.go` → `remoteBox` (sandbox.Box over IPC, later retired)
- `cmd/dizgin/autostart_windows.go` → UAC auto-elevation (later retired)
- Build/vet/test/cross-compile all passed at this snapshot

## Resolved (Iteration 1, 2026-03-28)

### ALT-A: Chromium wrapper ✓
- `restricted-exec` subcommand: self-restrict + CreateProcess WORKS
- Privilege stripping: all privileges stripped (only SeChangeNotifyPrivilege remains)
- Low IL: applied to process but also blocks workdir writes (Windows MIC more restrictive than expected)
- **Result:** Privilege-hardened sandbox (no admin required, no FS isolation)

### ALT-C: Admin broker fix ✓
- `enablePrivilege` bug: added ERROR_NOT_ALL_ASSIGNED check
- `LaunchRestrictedProcess`: added enablePrivilege("SeIncreaseQuotaPrivilege")
- `createRestrictedTokenFrom`: removed unnecessary DuplicateTokenEx
- Broker stdio bridge: nc.Close race fix + decoder buffer loss fix + pipe inheritance fix
- **Result:** CreateProcessAsUser WORKS, stdio bridge WORKS, privilege stripping WORKS

### ~~Remaining Issue: Full FS Isolation (R1)~~ RESOLVED

**Superseded by HCS Container approach.** The restricted-token + DACL path was abandoned in favor of HCS Container backend, which provides kernel-level filesystem isolation via bind mounts. All declared paths are mounted as `MappedDir` entries; undeclared paths are invisible to the sandboxed process. Red Line R1 is fully satisfied by the container backend.

## ~~Iteration 2: Restricting SIDs + DACL Performance~~ SUPERSEDED

**This section is historical.** The planned DACL + Restricting SID work is no longer needed because the HCS Container backend (implemented in `internal/sandbox/container/`) provides complete kernel-level FS isolation without DACL grants or token restrictions. The container namespace ensures only explicitly mounted directories are visible to the tool.

## Red Lines

| # | Red Line |
|---|----------|
| R1 | Full FS isolation — sandboxed tool can only access declared paths |
| R2 | Native experience — tool must not notice it's sandboxed |
| R3 | Go 1.25+ compatibility |
| R4 | `go build ./...` + `go vet ./...` + `go test ./...` all tests must pass |
| R5 | Cross-compile (darwin + linux) successful |
| R6 | macOS/Linux backends must not break |

## Verification

```bash
go build ./... && go vet ./... && go test ./... &&
GOOS=darwin go build ./... && GOOS=linux go build ./... &&
# With broker:
dizgin powershell -Command "whoami /priv"  # privileges stripped
dizgin powershell -Command "Get-ChildItem C:\Users\X\Desktop"  # BLOCKED
dizgin claude --version  # exit 0
dizgin claude -p "Say OK" --max-turns 1  # "OK", exit 0
```
