# Known Issue — Post-execution cleanup hang

**Status:** RESOLVED 2026-05-15 (timeout boundaries: A1 + A2 + A3)
**Severity (was):** CRITICAL (ship blocker — dizgin never returned control to user)
**Affected:** Windows only (`internal/daemon/stamp_broker_windows.go`,
`internal/sandbox/appcontainer/acl_windows.go`,
`internal/sandbox/appcontainer/box_windows.go`)
**First observed:** 2026-05-15 pre-launch smoke (`dizgin --no-pty echo hello` → exit 124)
**Discovered by:** manual smoke run + Heisenbug analysis (DIZGIN_DEBUG suppressed hang)

---

## Summary

After the child process exits and its output is written, `dizgin` hangs
indefinitely in its shutdown / `Cleanup` phase. The parent runner
observes exit code 124 (timeout-killed) after ~120 s. The Heisenbug
signature: enabling `DIZGIN_DEBUG=container|broker|pty` restores normal
behaviour because extra stderr writes perturb goroutine scheduling and
close the race window.

---

## Reproduction

```bat
REM Before fix — hangs ~120 s, then exit 124:
timeout 15 dizgin --no-pty cmd /c "echo CLEANUP_TEST"

REM After fix — exits in < 5 s:
timeout 15 dizgin --no-pty cmd /c "echo CLEANUP_TEST"
```

Observed before fix: `CLEANUP_TEST` printed, then prompt never returns.
After fix: exit 0, total elapsed < 5 s.

---

## Root cause

Six contributing sites, ordered by probability:

| # | Site | File | Sorun |
|---|------|------|-------|
| 1 | Daemon `icaclsRevoke` | `internal/daemon/stamp_broker_windows.go` | `exec.Cmd.Run()` no context/timeout — hung icacls (AV filter, USN journal) blocks daemon connection goroutine forever. **Primary cause.** |
| 2 | Daemon `icaclsGrant` | `internal/daemon/stamp_broker_windows.go` | Same pattern — hung grant blocks dizgin's Start phase for 120 s. |
| 3 | Dizgin `RevokePathForAppContainer` | `internal/sandbox/appcontainer/acl_windows.go` | `cmd.Run()` without timeout, called in Cleanup loop. |
| 4 | Dizgin IPC read deadline | `internal/daemon/client.go` | 120 s read deadline — the `exit 124` symptom originates here (parent runner kills dizgin at ~120 s). |
| 5 | `DeleteAppContainerProfile` | `internal/sandbox/appcontainer/profile_windows.go` | `userenv.dll` syscall without timeout; race with open handle / registry reaper. |
| 6 | stdin pump leak | `internal/sandbox/appcontainer/stdio_windows.go` | `os.Stdin.Read` not cancellable; benign goroutine leak (not a hang cause, hygiene only). |

---

## Fix

Three layers applied in the 2026-05-15 batch:

**A1 — Daemon icacls timeout (primary).**
`icaclsGrant` and `icaclsRevoke` in `stamp_broker_windows.go` now
accept a `context.Context`. All call sites pass
`context.WithTimeout(context.Background(), 15*time.Second)`. A hung
icacls subprocess is killed after 15 s and the error is logged at
`log.DebugSub(SubContainer, ...)`.

**A2 — Dizgin-side icacls timeout (symmetric).**
`StampPathForAppContainer` and `RevokePathForAppContainer` in
`acl_windows.go` create an internal `context.WithTimeout(..., 10*time.Second)`
and use `exec.CommandContext`. No public signature change.

**A3 — Cleanup guard helper.**
`runWithDeadline(name, d, fn)` in the new
`internal/sandbox/appcontainer/cleanup_guard_windows.go` bounds the
`revokeFn` IPC call and `DeleteProfile` syscall in `box.Cleanup` to
5 s each. A timeout logs at DebugSub and drops the goroutine (accepted
leak: dizgin is exiting, OS reaper handles residual state).

---

## Workarounds (before fix)

- `DIZGIN_DEBUG=container` — extra stderr writes perturbed scheduling and
  closed the race window. Explained the Heisenbug.
- Kill dizgin manually after output appears (`Ctrl+C`).

---

## Wire compatibility

Message shapes (`TypeStampPaths`, `TypeRevokeSid`, `StampSid`,
`StampPaths`, `StampPid`, `StampTTL`) are unchanged. All fixes are
server-side or dizgin-internal:

- New dizgin + old daemon: dizgin-side A3 guard returns after 5 s; old
  daemon's hung icacls is abandoned by the guard. Orphan sweeper (4 h
  TTL) cleans residual state.
- Old dizgin + new daemon: daemon icacls bounded at 15 s; old dizgin's 120 s
  read deadline never fires. No regression.

---

## Tracking

Regression tests added 2026-05-15:

- `tests/e2e/cleanup_post_exec_windows_test.go` —
  `TestCleanupPostExec_NoHang`: asserts dizgin exits in < 10 s.
- `internal/sandbox/appcontainer/cleanup_guard_windows_test.go` —
  `TestRunWithDeadline_HappyPath` / `TestRunWithDeadline_Timeout`:
  unit-tests the guard helper boundary.
