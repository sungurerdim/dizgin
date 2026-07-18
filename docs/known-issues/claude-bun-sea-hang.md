# Claude CLI hangs under AppContainer (Bun SEA binary) — RESOLVED

**Status: RESOLVED 2026-05-18 (iter6).** The hang was structural to
the AppContainer model — Windows AppContainer automatically applies
the **ACG (Arbitrary Code Guard) mitigation** to spawned processes,
and ACG hard-blocks Bun's in-process JavaScriptCore JIT at first
allocation. Iter5's four defence layers (TEMP override, PTAL handle
list, opt-in ETW trace, per-profile compatibility) addressed
adjacent symptoms but could not disable ACG on the AppContainer
spawn path.

Iter6 replaced the AppContainer backend with `restricted`
(`CreateRestrictedToken DISABLE_MAX_PRIVILEGE` + Medium IL + Job +
per-child `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` PTAL with **ACG
explicitly OFF in `DefaultPolicies`**, see
`internal/sandbox/restricted/mitigation_windows.go`). Bun's JIT
loads cleanly under the new backend; this hang shape is structurally
unreproducible on iter6's code path. See
[`CLAUDE.md`](../../CLAUDE.md) "Recently closed issues" → Iter6
entry for the full migration trail.

The iter5 mitigation layers documented below are preserved as
historical context and as documentation of what the iter5
verification harness checked.

---

**Original report (iter5, now historical):**

**Affected:** `dizgin --no-pty -- claude ...` on the (now-deleted)
Windows AppContainer backend. Even trivial invocations
(`claude --help`, `claude --version`) hung indefinitely with
CPU-active claude.exe but no output and no exit. Host invocations
succeeded in <1 s.

## Symptoms

- `dizgin --no-pty -- claude --help` produces no output past dizgin's own
  stamp-progress lines.
- claude.exe process is alive and consuming CPU (~270 s sampled over
  300 s wall clock). Not blocked on I/O — actively executing.
- Hang persists across these variations:
  - With or without `DIZGIN_DISABLE_PATH_MOUNTS=1`.
  - With persistent toolchain marker present (warm dizgin start, ~750 ms
    overhead before claude is invoked).
  - Stdin redirected to `/dev/null` (`echo "" | dizgin ...`).
  - Stdio routed through Node's `child_process.spawnSync` inside dizgin
    instead of dizgin's own pipe pump (different stdio inheritance path).
  - With `~/.claude/mcp.json` removed (no MCP server spawn attempts).

## Reproducer

```bash
./bin/dizgin.exe --no-pty -- claude --help
# Wait. Forever.
```

Sibling `dizgin --no-pty -- node --version` succeeds in 750 ms on the
same host, so dizgin's `--no-pty` owned-pipe infrastructure is healthy.

## What's been ruled out

1. **File mount visibility.** Direct test — adding `~/.claude.json` +
   `~/.claude` to a profile and reading them via `node` inside dizgin —
   returned the file contents with correct keys
   (`numStartups`, `hasCompletedOnboarding`, `claudeAiOauth`, ...). So
   the auth + onboarding state files ARE reachable inside the
   sandbox.
2. **Stdio pipe handling.** Node + powershell + cmd /c echo all
   work fine with `--no-pty`. Claude is the only tool exhibiting
   this hang.
3. **stdin blocking.** `echo "" | dizgin ...` providing immediate EOF
   on stdin does not unblock claude.
4. **MCP server spawn.** Renaming `~/.claude/mcp.json` away
   (effectively disabling MCP discovery) does not unblock claude.
5. **Toolchain stamp cost.** The 49 s `~/go` propagation cost was
   measured and fixed in `0053c0e` / `65ed45c`; claude hang persists
   long after the per-session work is done (claude.exe starts in
   ~3 s, then hangs indefinitely after that).

## Hypotheses still on the table

1. **Bun SEA runtime + AppContainer interaction.** Claude Code is a
   Bun SEA-packed binary. Bun's libuv backend may use Windows APIs
   (async I/O completion ports, specific cert-store reads, or
   undocumented kernel handles) that AppContainer's LowBox token
   denies silently. Node uses a different libuv shape and works fine.
2. **TLS / cert store access.** Claude makes outbound HTTPS to
   `api.anthropic.com`. AppContainer-restricted processes accessing
   the per-user cert store may need a capability we don't grant.
   Test would be: try claude with `network: blocked` policy and see
   if it fails fast with a clear network error, or still hangs (which
   would rule TLS out).
3. **Onboarding loop without TTY.** Claude reads
   `hasCompletedOnboarding` from `~/.claude.json`. We verified the
   field is readable, but maybe claude's check fails for a different
   reason (file is mounted as a single-file `Mount` and gets a per-
   session AC SID ACE, which works for `readFileSync` from Node but
   may behave differently when claude opens the file under Bun's
   runtime).

## Iter5 net change (2026-05-18)

Iter5 shipped a 4-layer surgical fix that addressed the leading
hypothesis (Bun SEA `%TEMP%` extract) plus two defence-in-depth
hardening passes and an opt-in diagnostic. Each layer is
independently revertable via an env-var emergency switch.

| Layer | Mechanism | Opt-out |
|-------|-----------|---------|
| L1 | Per-session `TEMP`/`TMP`/`TMPDIR` redirected to AC-SID-stamped scratch dir so Bun's `$bunfs` extract has a writable target | `DIZGIN_NO_TEMP_OVERRIDE=1` or `compatibility.temp_override: false` |
| L2 | `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` PTAL entry — only the three stdio handles inherit; ambient dizgin handles dropped | `DIZGIN_NO_HANDLE_LIST=1` or `compatibility.handle_list_allowlist: false` |
| L3 | Opt-in ETW permissive-learning trace via logman/tracerpt (Microsoft-Windows-Kernel-General, keyword 0x20). Prints denial summary on child exit. Admin required (kernel-mode session) | `DIZGIN_ETW_PERMISSIVE_LEARN=1` to turn ON |
| L4 | Per-profile `compatibility:` YAML block — knobs for L1, L2, and forward-looking mitigations (`allow_dynamic_code`, `allow_low_label_images`) so future hardening waves can ship with profile-level escape hatches without breaking strict YAML parse | — |

**Verify state on commits 8e75570 → 2fa3b61:** `claude --version`
still hangs at the 60 s timeout boundary. `node --version` still
exits in 750 ms — zero regression. Suite is 466 PASS (iter4 was
442). `go build ./...`, `go vet ./...`, `govulncheck ./...` all
clean.

The TEMP override hypothesis turned out to be incomplete: Bun
SEA does need a writable %TEMP%, but the still-active hang means
there is at least one more denial point. Layer 3 ETW trace
(run as admin) is the canonical iter6 entrypoint to surface it.

## Next steps when picked up (iter6 entrypoint)

1. **Layer 3 ETW trace under admin.** Run
   `DIZGIN_ETW_PERMISSIVE_LEARN=1 dizgin --no-pty -- claude --version`
   from an elevated shell. The exit-time stderr summary lists up
   to 10 DENIED kernel access events with object names; tail the
   CSV in the printed path for the full list.
2. **Process Monitor capture** with filter
   `Process Name = claude.exe AND Result contains ACCESS DENIED`
   — Sysinternals procmon is the visual companion to Layer 3.
3. **Compare with a vanilla Bun SEA binary** (not Claude Code).
   Build a "hello world" Bun SEA, run it inside dizgin. If it also
   hangs, the issue is Bun ↔ AppContainer; if it works, the issue
   is Claude Code-specific.
4. **Try `dizgin -- claude ...` with PTY mode** (no `--no-pty`).
   ConPTY is a separate stdio path that uses a pseudo-console
   handle. If claude completes under PTY but hangs under
   `--no-pty`, the bug is in pipe vs ConPTY interaction with
   AppContainer.
5. **Strace-style debugging via WinDbg attach** on the AppContainer
   process. Get a stack trace of the active thread.

## Workarounds

- **None at the dizgin layer.** The hang is below the dizgin boundary
  even after iter5's L1+L2.
- Running claude **outside** dizgin works fine — for the duration this
  issue is open, users should invoke claude directly when dizgin is
  otherwise their preferred wrapper.
