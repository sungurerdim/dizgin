# Windows Sandbox: Tried Approaches & Solution

## Problem

Creating a restricted-token child process on Windows requires privileges not available to
normal users. This document records the approaches tried and the final solution.

## Tried Approaches

### 1. CreateProcessWithTokenW (FAILED)

```
CreateRestrictedToken(DISABLE_MAX_PRIVILEGE) → restricted token
CreateProcessWithTokenW(restrictedToken, LOGON_WITH_PROFILE, ...) → ERROR_PRIVILEGE_NOT_HELD
```

**Cause:** `SeImpersonatePrivilege` required. Not available to normal users.
**MSDN:** "The process that calls CreateProcessWithTokenW must have the SE_IMPERSONATE_NAME privilege."

### 2. CreateProcessAsUser (FAILED)

```
CreateRestrictedToken(DISABLE_MAX_PRIVILEGE) → restricted token
CreateProcessAsUser(restrictedToken, ...) → ERROR_PRIVILEGE_NOT_HELD (1314)
```

**Cause:** `SeIncreaseQuotaPrivilege` required. Not available to normal users.
**MSDN:** "SE_ASSIGNPRIMARYTOKEN_NAME privilege is not required [for restricted tokens]" — true,
but `SE_INCREASE_QUOTA_NAME` is still required.

### 3. NtSetInformationProcess (FAILED)

```
CreateProcess(SUSPENDED) → child with normal token
NtSetInformationProcess(child, ProcessAccessToken, restrictedToken) → STATUS_PRIVILEGE_NOT_HELD (0xc0000061)
```

**Cause:** `SeAssignPrimaryTokenPrivilege` required. Kernel-level requirement — no bypass.

### 4. Self-Restrict then CreateProcess (FAILED)

```
AdjustTokenPrivileges(ownToken, DisableAll) → own token restricted
CreateProcess(...) → ERROR_ACCESS_DENIED
```

**Cause:** After stripping own token, even `CreateProcess` can't be called.
Token restriction is irreversible.

### 5. CreateProcess(SUSPENDED) then Self-Restrict (INSECURE)

```
CreateProcess(SUSPENDED) → child created with FULL token (copied at creation time)
AdjustTokenPrivileges(ownToken, DisableAll) → parent restricted (irrelevant)
ResumeThread(child) → child runs with FULL UNRESTRICTED token
```

**Result:** Child process runs with full privileges. `whoami /priv` shows all privileges.
Medium Integrity Level. Desktop, Documents, system files — all readable and writable.
**No FS isolation.** Red Line #1 violated.

### 6. Thread Impersonation + CreateProcess (RESEARCHED, NOT IMPLEMENTED)

**Result:** CreateProcess passes the primary token to the child, not the thread impersonation token.
MSDN: "By default, when you create a child process it inherits your primary token even if you
are currently impersonating another security context."

### 7. PROC_THREAD_ATTRIBUTE_TOKEN (RESEARCHED, NOT IMPLEMENTED)

This attribute doesn't exist in the Windows API. `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` is
for containers, not general token assignment.

### 8. Job Object FS Restriction (RESEARCHED, NOT IMPLEMENTED)

Job Objects don't restrict filesystem access. They only provide resource limits (CPU, RAM, PID)
and process creation (breakaway) control.

## Solution: Restricted token + Medium IL + Job Object + DACL DENY (iter6+, per-session, non-admin)

**Why it works:** `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` can be called from any user token without elevated privileges — the restricted token is a subset of the caller's own token. The kernel enforces the privilege strip. DIZGIN pairs this with a DENY-list model for filesystem isolation: a small set of 19 sensitive credential surfaces receive explicit DENY ACEs via `SetNamedSecurityInfo`; all other paths are governed by the user's existing NTFS rights. The tool process runs at **Medium IL** (`S-1-16-8192`) so it can still access the workdir and tool config dirs without any additional GRANT stamps.

> **History:** The previous iteration (iter5 and earlier) used AppContainer + LowBox + Low IL (`S-1-16-4096`) + per-session AC SID grants via `icacls`. That model was retired in iter6 because AppContainer's ACG (Arbitrary Code Guard) requirement caused a hard hang with Bun's in-process JIT (CLAUDE-HANG-01). The current backend sets ACG **OFF** explicitly, resolving the hang. The AppContainer approach is preserved in the "Tried Approaches" section above for historical reference.

**Flow:**
1. dizgin calls `CreateRestrictedToken(existingToken, DISABLE_MAX_PRIVILEGE, nil, nil, nil)` to produce a privilege-stripped token at Medium IL (`S-1-16-8192`).
2. dizgin enumerates the 19 SSOT sensitive paths from `internal/security/sensitive_paths_windows.go` and calls `SetNamedSecurityInfo` on each existing path to add a `DENY` ACE (`GENERIC_ALL` + `OI`+`CI` inheritance). Any path that does not exist is skipped. If any stamp fails, dizgin aborts and rolls back all applied DENY ACEs before returning an error — partial state is never left behind.
3. dizgin builds a `STARTUPINFOEX` with `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` (DEP ON, ASLR force-relocate + high-entropy ON, ImageLoad NoRemote/NoLowLabel/PreferSystem32 ON, StrictHandleChecks ON, ACG **OFF**) and `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` (only the three stdio handles inherit). On ConPTY sessions a pseudoconsole handle is also inherited.
4. `CreateProcessAsUserW` launches the tool under the restricted token. The process is immediately assigned to a Job Object with `KILL_ON_JOB_CLOSE` + memory cap + PID cap + UI restrictions.
5. On exit, `Box.Cleanup` revokes the DENY ACEs via a tree-walk using `SetNamedSecurityInfo` with `SET_ACCESS` (zero perms). `SET_ACCESS` strips both DENY and GRANT ACEs, working around the documented `SetEntriesInAcl REVOKE_ACCESS` asymmetry (REVOKE only removes ACCESS_ALLOWED ACEs).

**No admin daemon required for sandbox creation.** `dizgind` runs as a normal-user daemon for IPC, suspend/resume, and WFP network-allowlist brokering. WFP filter installation requires elevation; dizgin sends `wfp_apply`/`wfp_revoke` IPC messages to the elevated dizgind daemon rather than installing filters directly.

**Red lines:**
- **R1 (Sensitive Surface Isolation):** ✓ 19 SSOT credential paths get DENY ACEs at session start; any attempt to open them returns `ERROR_ACCESS_DENIED`. Revoked on exit. Sensitive paths are never auto-granted — even `--learn` requires an explicit user decision for SSOT paths.
- **R2 (Native Experience):** ✓ Tool runs as a real Win32 process with native paths (`host_path == guest_path`), inherited stdio, ConPTY for interactive sessions, full `\\.\pipe\dizgin-dizgind` access. No shim, no path remap, no UVM boot.

## DENY-stamp pipeline

The Windows backend does not bind-mount. Filesystem isolation is DENY-ACE-based, not grant-based:

| Step | Actor | Effect |
|------|-------|--------|
| 1 | dizgin process | `buildSensitiveDenyJobs` reads the 19 SSOT paths from `internal/security/sensitive_paths_windows.go`, expanding `%USERPROFILE%` and skipping paths that do not exist |
| 2 | dizgin process | `StampPathDeny(path)` calls `SetNamedSecurityInfo` with a `DENY` ACE (`GENERIC_ALL` + `OBJECT_INHERIT_ACE` + `CONTAINER_INHERIT_ACE`) on each path |
| 3 | dizgin process | On any stamp failure, `rollbackDenyStamps` calls `SetNamedSecurityInfo` with `SET_ACCESS` (zero perms) on every successfully stamped path before returning the error |
| 4 | dizgin process | `Box.Start` creates the tool under the restricted Medium-IL token; the tool inherits only the three stdio handles (or ConPTY handle for interactive sessions) |
| 5 | tool | Reads / writes host paths directly. Sensitive SSOT paths return `ERROR_ACCESS_DENIED`; all other paths obey the user's existing NTFS ACL |
| 6 | dizgin process (post-exit) | `Box.Cleanup` revokes DENY ACEs via tree-walk: `SetNamedSecurityInfo(SET_ACCESS, 0)` — strips both DENY and GRANT ACEs (REVOKE_ACCESS asymmetry workaround) |

## IDE Integration (VSCode / JetBrains)

When an editor is open on the host workdir (e.g. `D:\GitHub\dizgin` in VSCode) and `dizgin <tool>` runs from a separate terminal, the host file watcher observes changes the tool makes. The mechanism:

- `host_path == guest_path`: the tool runs as the same user on the same NTFS inode the host sees.
- Windows file-change notifications (ReadDirectoryChangesW) fire on the host and the editor refreshes.
- No staging tree, no SyncBack — there is no "post-exit" persistence step because the writes were always on the host filesystem to begin with.

**VSCode:**
- File tree, editor tabs, and extensions that use `workspace.createFileSystemWatcher` pick up tool edits within the normal notification latency (~100 ms).
- Tested flow: open workdir in VSCode → run `dizgin claude` in terminal → ask Claude to edit a file → VSCode shows the change inline.

**JetBrains (GoLand / IDEA / PyCharm):**
- Same mechanism; Fsnotify-equivalent watcher detects tool writes.
- The IDE's internal VFS cache may lag briefly; Ctrl+Alt+Y (`File > Reload All from Disk`) forces an immediate resync if needed.

**Paths OUTSIDE the workdir (host user profile, MCP dirs, toolchains):** accessible to the tool under the user's natural NTFS rights, except for the 19 DENY-listed sensitive paths. The IDE on the host can also see them — there is no isolation barrier between editor and tool for paths both are allowed to read.

**Not supported:** simultaneous writes to the same file from both the host editor and the tool. NTFS will serialise them, but no conflict resolution is performed — last writer wins.

## References

- [MSDN: CreateRestrictedToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)
- [MSDN: Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [MSDN: SetNamedSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfow)
- [MSDN: Process Mitigation Policy (PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [MSDN: Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)
- [MSDN: AppContainer Isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation) (historical — retired in iter6)
- [Chromium Sandbox Design](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/design/sandbox.md)
