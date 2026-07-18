# Iter6 — AppContainer → restricted Backend Refactor (tasks)

**STATUS: ALL 6 PHASES SHIPPED 2026-05-18.** Commits 3bc2513 (Faz 1)
→ 721a1a5 (Faz 2) → 9097878 (Faz 3) → 46473da (Faz 4) → b9f7c3c (Faz 5)
→ Faz 6 (this commit). CLAUDE-HANG-01 closed; AppContainer package
deleted (~-5800 LOC net); restricted is the sole Windows backend.

R2 (path identity) korundu. WSL2 + Junction yaklaşımları elendi.

## Faz 1 — Skeleton + Token Refactor

- [x] `internal/sandbox/restricted/backend.go` — Backend stub (Name/Available/Create)
- [x] `internal/sandbox/restricted/backend_other.go` — non-Windows no-op
- [x] `internal/sandbox/restricted/token_windows.go` — fork; Medium IL parametrik (`S-1-16-8192`); NtCreateLowBoxToken yok
- [x] `internal/sandbox/restricted/job_windows.go` — copy (paket adı değişir)
- [x] `internal/sandbox/restricted/handle_list_windows.go` — copy
- [x] `internal/sandbox/restricted/cleanup_guard_windows.go` — copy
- [x] `internal/sandbox/restricted/mitigation_windows.go` — YENİ; DEP ON, ASLR force, ACG OFF; BlockNonMicrosoftBinaries opt-in
- [x] `internal/sandbox/names.go` — `BackendNameRestricted = "restricted"`
- [x] Test: `TestCreateRestrictedTokenMediumIL` — token IL `S-1-16-8192`
- [x] Test: `TestMitigationPoliciesApplied` — `GetProcessMitigationPolicy` ile DEP/ASLR ON, ACG OFF

Gate: `go build ./...` cross-platform yeşil; iki test geçer; **AppContainer hâlâ default backend** (side-by-side).

## Faz 2 — Sensitive DENY SSOT + FS Model

- [x] `internal/security/sensitive_paths_windows.go` — `SensitiveDenyPaths(userProfile string) []string` (11+ relative path: .ssh, .aws/credentials, .gnupg, .netrc, .docker/config.json, .kube, browser cookie stores, DPAPI vault)
- [x] `internal/security/path_classify_windows.go` — `IsSensitiveDeny(path string) bool` eklenir
- [x] `internal/sandbox/restricted/acl_windows.go` — `StampPathDeny` + `StampPathGrant` (user SID trustee); DENY ACE her zaman grant'ten önce
- [x] `internal/sandbox/restricted/stamp_parallel_windows.go` — fork (`acSid` → `trustee *windows.SID`)
- [x] Test: `TestSensitiveDenyPathsExpanded` — 11 path doğrulanır
- [x] Test: `TestDenyACEPrecedesGrant` — DACL'da deny index < grant index
- [x] Test: `TestIsSensitiveDeny` — `.ssh\id_rsa` true, `.claude` false

Gate: tüm sensitive testler geçer; DACL deny-first sıralaması assert edilir.

## Faz 3 — Box + Backend Registration + Config

- [x] `internal/sandbox/restricted/box_windows.go` — Start() sıra: token → scratch → job → mitigation → DACL stamp → PTAL → CreateProcessAsUserW → AssignProcessToJob → stdio pumps
- [x] `internal/sandbox/restricted/stdio_windows.go` — adapt; pipe SD'de user SID grant (AC SID yerine)
- [x] `internal/sandbox/restricted/scratch_windows.go` — per-session temp dir
- [x] `cmd/dizgin/backends_windows.go` — `_ "...sandbox/restricted"`; `DIZGIN_BACKEND=appcontainer` env override
- [x] `internal/config/config.go` — `compatibility.mitigation_policy.block_non_microsoft_binaries` (default false)
- [x] Test: `dizgin echo hello` smoke (no hang)
- [x] Test (kritik): `dizgin --no-pty -- claude --version` < 2s — **CLAUDE-HANG-01 kapanır**
- [x] Test: sensitive DENY — `dizgin -- cmd /c type %USERPROFILE%\.ssh\id_rsa` → Access denied

Gate: Faz 3 sonrası **daily-driver kalite**.

## Faz 4 — AppContainer Silme + Dizgind Refactor

**Silinen production (~1050 LOC):**
- [x] `internal/sandbox/appcontainer/profile_windows.go` (~180)
- [x] `internal/sandbox/appcontainer/network_windows.go` (~80)
- [x] `internal/sandbox/appcontainer/persistent_stamp_windows.go` (~120)
- [x] `internal/sandbox/appcontainer/depresolver_windows.go` (~200)
- [x] `internal/sandbox/appcontainer/depresolver_cache_windows.go` (~150)
- [x] `internal/sandbox/appcontainer/peimport_windows.go` (~180)
- [x] `internal/sandbox/appcontainer/etw_permissive_windows.go` (~100)
- [x] `internal/sandbox/appcontainer/integrity_label_windows.go` (~40)
- [x] `cmd/dizgind/setup_windows.go` — AC SID grant bloğu (~180)

**Silinen test (~530 LOC):**
- [x] `*_bench_windows_test.go`, `*_memo_windows_test.go`
- [x] `etw_permissive_windows_test.go`
- [x] `acl_windows_test.go` capPolicy bloğu
- [x] `backend_test.go` capPolicy

**Refactor (-250 LOC net):**
- [x] `appcontainer/box_windows.go` — `SECURITY_CAPABILITIES` + `appContainer SID` + `caps` alanları kaldırılır
- [x] `appcontainer/stamp_parallel_windows.go` — `acSid` → `trustee *windows.SID`
- [x] `appcontainer/stdio_windows.go` — `buildAcSidGrantSD` → user SID
- [x] `cmd/dizgind/setup_windows.go` — sadece `%ProgramData%\dizgin` dir + marker

Gate: cross-platform build + e2e Windows yeşil; `dizgind setup --check` hata vermez.

## Faz 5 — Permission Learning Mode

- [x] `cmd/dizgin/main.go` — `--learn` flag (+25 LOC)
- [x] `internal/sandbox/restricted/learn_windows.go` — accessRecorder, stderr intercept (~180)
- [x] `internal/sandbox/restricted/learn_prompt_windows.go` — batch prompt + YAML kaydet (~120)
- [x] `dizgin --learn -- tool args` → WORKDIR-only DENY; çıkışta batch prompt
- [x] Karar `~/.dizgin/permissions/<tool>.yaml`'e kaydedilir
- [x] Sonraki normal çalıştırma bu dosyayı otomatik okur

## Faz 6 — Doc + YAML Schema + Migration

- [x] `docs/SECURITY.md` — "AppContainer SID stamp" → "Restricted Token + DENY ACE"; R7 güncelle
- [x] `docs/CONFIG.md` — `compatibility.mitigation_policy.*` + `permissions.auto_grant.*`
- [x] `CLAUDE.md` — restricted backend; kaldırma sebebi
- [x] `docs/ROADMAP.md` — AppContainer "Completed (replaced by restricted)"; WFP DNS Q3 2026
- [x] `docs/known-issues/claude-bun-sea-hang.md` — RESOLVED
- [x] `profiles/*.yaml` manuel review — çoğu artık gereksiz; minimal set

## Risk

1. **Bun yine hang (ACG dışı sebep)** — `CreateRestrictedToken`'de `SidsToDisable`/`RestrictedSids` boş kalır. Fallback: `DIZGIN_RESTRICTED_MINIMAL=1` → sadece Job + Mitigation.
2. **Permission Learning stderr parse zayıf** — Faz 5 deferred MVP'yi bozmaz. Aktive edilirse `DIZGIN_LEARN_PATHS` env var manuel fallback.
3. **E2e testlerin %30+'ı kırılır** — AC SID-spesifik assertion'lar Faz 4'te adapte edilir.

## Toplam LOC delta: ~-1680 (appcontainer paketi ~%42 küçülür)
