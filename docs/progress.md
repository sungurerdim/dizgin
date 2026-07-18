# DIZGIN — Progress Log

Active milestones and roadmap for the DIZGIN project. Historical
incident archaeology from the retired HCS Hyper-V container path
(2025-Q4 → 2026-04 inclusive) lives in
[`history/progress-hcs.md`](history/progress-hcs.md) — that file is
preserved for forensic context but is no longer part of the active
documentation surface.

For the canonical run history (blueprint scores, audit deltas, ds-fix
batches), see the **Run History** section in [`../CLAUDE.md`](../CLAUDE.md).

---

## Current State

- **2026-05-19 — iter7 (`dizgind setup` removed).** The restricted
  token preserves `SeChangeNotifyPrivilege`, so NTFS bypass-traversal
  works under the user's natural ACL — no admin-once host-side ALL
  APPLICATION PACKAGES grant remains. dizgin runs from cold install with
  zero UAC prompts. `dizgind heal` (DACL drift scan + `--apply`
  revoke) is the post-incident recovery successor.

- **2026-05-18 — iter6 (AppContainer → `restricted` backend).**
  CLAUDE-HANG-01 closed structurally: the restricted backend never
  applies ACG, so the Bun-SEA JIT collision cannot reproduce. Windows
  production backend is now `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)`
  + Medium IL (`S-1-16-8192`) + Job Object + per-child Process
  Mitigation Policies (DEP/ASLR ON, ACG OFF) + DACL DENY ACEs on the
  sensitive-credential SSOT. The AppContainer package was deleted
  (~-5800 LOC net); WCT diagnostic extracted to
  `internal/diagnostic/wct/`.

- **2026-05-18 — iter4 closure (3-tier R model + sweep + UX overhaul).**
  Net ~6.9K LOC removed (web dashboard, TUI, userspace DNS proxy,
  5-way exit prompt, `dizgin unstamp`/`audit-low`, dual ACL paths, dead
  stubs) + ~620 LOC added (SSOT helpers, audit/mount, `dizgin add-path`,
  3-tier classifier, category-aware error hints). AppContainer DACL
  stamping consolidated to in-process `SetNamedSecurityInfo` only —
  iter3's icacls shellout retired. Mount.Category enum routes stamps
  through the classifier; RO mounts use `FILE_GENERIC_READ +
  FILE_TRAVERSE` instead of `GENERIC_READ | GENERIC_EXECUTE`. Tests
  588 → 442 PASS (deletions accounted for; no regressions). Build /
  vet / govulncheck clean. See [`ROADMAP.md`](ROADMAP.md) for what was
  deferred and why. Audit score 99 → 100.

- **2026-05-17:** Phase 1 hardening sweep complete. GATE-A: build+vet+588
  tests+golangci-lint 0+govulncheck 0 all green; Go 1.26.3 bump fixes 2
  CVEs (GO-2026-4971, GO-2026-4918). GATE-B: R1 fail-closed and R2 node
  path-identity confirmed live; new open finding R2-02 (MSYS2 getcwd()
  fails under Low IL). GATE-C: SECURITY.md R2 evidence pointer
  corrected, dead `internal/telemetry/` scaffold dropped. Test fix: TST-03
  path_identity CombinedOutput mixing corrected. Audit score 93→95.

- **2026-05-15:** Post-execution cleanup hang closed (BUG-04). Timeout
  boundaries added to all `icacls` subprocess calls (daemon: 15 s,
  dizgin: 10 s) and a `runWithDeadline` guard (5 s) wraps `revokeFn` IPC
  + `DeleteProfile` in `box.Cleanup`. R2-01 `--no-pty` regression test
  added (`TestNoPtyStdio_OutputCaptured`). Wire format unchanged.

- **Production backend (Windows):** restricted token
  (`CreateRestrictedToken DISABLE_MAX_PRIVILEGE`) + Medium IL + Job
  Object + per-child Process Mitigation Policies (ACG OFF) + DACL DENY
  ACEs on the sensitive SSOT. Single backend per platform; the
  no-fallback policy is enforced at `Backend.Create` time.
- **Production backend (macOS):** Seatbelt (`sandbox-exec`) with SBPL
  profiles.
- **Production backend (Linux):** bubblewrap (`bwrap`) with user
  namespaces and seccomp-BPF.
- **Daemon:** `dizgind` owns the IPC pipe (`\\.\pipe\dizgind` on
  Windows, unix socket on Unix) and the session registry. The
  restricted backend stamps DACL DENY ACEs in-process at session
  start — there is no stamp-delegation broker (the iter6 migration
  retired it along with the AppContainer SID).
- **No TUI / web dashboard.** Both were retired in iter4. Inspection
  goes through `dizgind status`, `dizgind status --json`, and `dizgin
  doctor`.

---

## 2026-05 — Pre-launch foundation

- Root `SECURITY.md`, Code of Conduct, issue and PR templates,
  Dependabot, CodeQL, release workflow added under `.github/`.
- Locale-agnostic access telemetry: regex layer extended with
  multi-locale anchors and a non-zero-exit args-fallback that flags
  every absolute-path argv element that does not exist on the host
  filesystem.
- Daemon graceful degradation: `DIZGIN_NO_DAEMON_AUTOSTART=1` env var
  bypasses autostart for tests and CI; warm-start wait reduced from
  60 s to 15 s.
- Makefile `e2e:` target now stages `dizgin`/`dizgind` binaries into
  `tests/e2e/testdata/` so the integration suite stops silently
  skipping.
- Critical-path coverage uplift: `internal/log` and
  `internal/sandbox/appcontainer` happy-path tests added.
- Documentation drift cleanup: `ipc:` field documented as
  informational-only in `docs/CONFIG.md`.

---

## Roadmap

| Milestone           | Status      | Notes                                                              |
|---------------------|-------------|--------------------------------------------------------------------|
| Windows MVP         | shipped     | restricted-token backend, dizgind daemon                           |
| macOS port          | shipped     | Seatbelt SBPL profiles                                             |
| Linux port          | shipped     | bubblewrap, R1 cover-mounts; network allowlist not yet enforced (fails fast) |
| iter4 consolidation | shipped     | 3-tier R model, marginal-feature sweep, UX overhaul (2026-05-18)   |
| Public 0.1.0 launch | next        | Iter4 cleared the runway; tag + release workflow trigger pending   |
| Prometheus exporter | roadmap     | Replacement for retired web dashboard (see `docs/ROADMAP.md`)      |
| WFP DNS allowlist   | roadmap     | Kernel-level replacement for retired userspace DNS proxy           |
| shimV2 reactivation | tracked     | Microsoft Hyper-V isolation path (Q3-Q4 2026 window)               |

---

## Source material

- Active session decisions: see commit history (`git log --since=2026-04`).
- Blueprint score history: `CLAUDE.md` → "Run History".
- Pre-AppContainer HCS-era incidents: `docs/history/progress-hcs.md`.
