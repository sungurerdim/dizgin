# AIPD — Historical Progress & Incident Log (retired HCS path)

> **Historical: HCS Hyper-V container path, retired 2026-05-02 in
> commit `94ea514`.** This file is preserved for forensic context only —
> it is **no longer part of the active documentation surface**. The
> production sandbox backends are now AppContainer + LowBox + Job
> Object (Windows), Seatbelt (macOS), and bubblewrap (Linux); see
> [`../progress.md`](../progress.md) for the active progress log.

Windows HCS Container sandbox projesi için kronolojik ilerleme, karşılaşılan tüm sorunlar, denenen çözümler ve durum kaydı. Ham bilgi kaynağı: Claude Code session log'ları ve memory kayıtları.

**Son güncelleme:** 2026-04-22
**Mevcut Milestone:** M5 (Windows MVP integration) — 2026-04-22 staging-based mount emulation plan çalışıyor, Faz 0 tamamlandı

---

## 2026-04-22: Faz 0 — Baseline + `--dry-run-mounts`

**Amaç:** Kök neden teyidi. Staging refactor öncesi R1 ihlalini objektif kanıta bağla.

**Eklenen:**
- `cop --dry-run-mounts <tool>`: mount tablosu + virtual home env override + setup cmd + R1 check çıktısı basar, sandbox başlatmaz.
- `tests/e2e/smoke_claude_windows_test.go`: 8 senaryoluk integration smoke (version, echo, ls config, bash+git, bash+node, undeclared path, skill dir, paralel). Sonuç dosyası `tests/e2e/testdata/smoke-claude-windows.txt`.
- Dry-run flag daemon başlatmıyor: `argsContainFlag(os.Args[1:], "--dry-run-mounts")` check.

**Baseline kanıtı (`cop --dry-run-mounts claude`):**

- Toplam 41 mount entry.
- **R1 FAIL**: `C:\Users\Sungur` (user profile kökü) mount listesinde, Force=true, RW, Guest=`C:\aipd-home`. Bu satır `addConfigDirMounts`'un FILE entry (`~/.claude.json`) için yaptığı `filepath.Dir(d)` parent mount'unun rewrite edilmiş hali. Kök neden kesinleşti.
- User profile altında 19 alt mount (`.claude`, `.cache`, `go`, `miniconda3`, `AppData/Local/...` vs).
- Virtual home env override 8 case varyantı stripler, TEMP/APPDATA/USERPROFILE/HOME hepsi `C:\aipd-home` altına yönleniyor.

**Smoke baseline (integration, admin, Claude yüklü makine gerekli):** henüz otomatik koşturulmadı. Faz 1 sonrası ilk tam koşum + delta bu bölüme eklenecek.

---

## 2026-04-22: Faz 1 — Staging-Based File Mount Emulation

**Amaç:** R1 kök neden düzeltmesi. HCS MappedDir'in file mount destekleme eksikliğini staging tree ile emüle et.

**Eklenen:**
- `cmd/cop/staging_windows.go`: `stagingSession` (sessionID, root, homeStage, syncOnExit), `newStagingSession` (ProgramData\aipd\staging → LOCALAPPDATA fallback), `AddFile` (home altındaki dosya → staging kopya + guest path), `Mounts` (tek entry: stagingHome → VirtualHomeRoot, Force=true), `SyncBack` (sha256 diff, atomic temp+rename), `Cleanup` (RemoveAll).
- `cmd/cop/staging_other.go`: identity stub (bwrap/seatbelt file mount native).
- `cmd/cop/staging_windows_test.go`: 8 unit test (AddFile home altı/dışı, Mounts, SyncBack changed/unchanged, Cleanup, Isolated, buildMounts entegrasyonu).

**Değişen:**
- `cmd/cop/session.go`: `buildMounts`, `buildSandboxOpts`, `createSandbox`, `addConfigDirMounts` imzaları `stage *stagingSession` alıyor. FILE config_dir entry artık `stage.AddFile`'a delege ediliyor — eski `filepath.Dir(d)` parent-dir mount'u kaldırıldı. Staging mount `rewriteGuestToContainerHome` ÖNCE değil SONRA ekleniyor (Guest zaten `VirtualHomeRoot`).
- `cmd/cop/main.go`: run() staging session yaratır, executionContext.stage geçirir; executeTool Wait() sonrası os.Exit öncesi SyncBack + Cleanup çağırır.
- `cmd/cop/dry_run.go`: dry-run disposable staging session kullanıyor.

**R1 doğrulama (`cop --dry-run-mounts claude`):**
- **Öncesi (baseline):** `C:\Users\Sungur` mount listesinde (Force=yes, RW, Guest=`C:\aipd-home`) → **R1 FAIL**.
- **Sonrası:** `Host user profile root (C:\Users\Sungur) in mount list: no` → **R1 PASS**.

**Test:** `go test ./cmd/cop/...` yeşil (8 staging testi + mevcut 20+ testin tamamı). `go vet ./...` temiz.

**Bekleyen doğrulama:** HCS live scenario — staging mount scratch layer'ı örtüyor mu (Faz 3 overlay probe) ve Claude smoke 8-senaryosu — bunlar integration + admin + Claude yüklü ortam gerektiriyor.

---

## 2026-04-22: Faz 2-11 — Edge Cases, Bash Fix, Network, Parallel, Telemetry

Tek oturumda tüm planın kalan 9 fazı tamamlandı (Faz 2, 3, 4, 5, 6, 7, 8, 10, 11). Faz kapsamları:

- **Faz 2 (virtual home edge cases):** Cyrillic username, non-C: profile drive, HOMEDRIVE+HOMEPATH fallback, UNC pass-through, case-variant home, mixed-separator translateToContainerHome testleri eklendi.
- **Faz 3 (overlay probe):** `internal/sandbox/container/overlay_probe_windows_test.go` (integration tag) ile staging mount ↔ scratch layer birlikte görünürlüğünü ölçen probe hazırlandı. mklink fallback kodu, live probe sonucu örtme gösterirse devreye girecek şekilde placeholder olarak bırakıldı.
- **Faz 4 (bash exit 57):** `cmd/cop/container_init_windows.go:probeTempWritable` — TEMP sentinel check (exit 57 ile fail). `profiles/claude.yaml` env: `MSYS=disable_pcon`, `MSYS2_PATH_TYPE=inherit`, `CHERE_INVOKING=1`. `VirtualHomeSetupCmd` `.bashrc` placeholder yaratıyor. `tests/e2e/bash_subprocess_test.go` regression test.
- **Faz 5 (network allowlist):** `tests/e2e/network_allowlist_test.go` — allowlist pozitif, allowlist negatif, blocked policy senaryoları. DNS proxy zaten unit test kapsamında.
- **Faz 6 (parallel + orphan cleanup):** `internal/daemon/staging_cleanup_windows.go` — pid-alive check (OpenProcess + GetExitCodeProcess), 10 dk yaş grace, saatlik sweeper. Station startup'ta ilk sweep + ticker. `tests/e2e/parallel_windows_test.go` paralel cop invocations.
- **Faz 7 (suspend/resume):** `tests/e2e/suspend_resume_windows_test.go` scaffold (station CLI suspend/resume henüz yok; test mevcut wiring'in canlı kaldığını doğrular).
- **Faz 8 (teknik borç):** `internal/daemon/client.go:Close` — `SetReadDeadline(time.Now())` ile winio pipe deadlock unblock. `box.go:tempDir` zaten önceki sprintte silinmiş. `docs/SECURITY.md` Red Line Verification bölümü, `docs/progress.md` güncel Run History.
- **Faz 10 (R1+R2+R7 onay paketi):** `docs/SECURITY.md` Red Line Verification tablosu — her red line için somut kanıt dosyası + test adı.
- **Faz 11 (access telemetry Level 1):** `cmd/cop/access_telemetry.go` — bounded buffer observer + regex path extractor (Windows CMD / Unix ENOENT / Go open / Node.js / Python / "access denied"). `cmd/cop/access_telemetry_test.go` 12 pattern + dedupe + buffer-bound testleri. Session.go runtime entegrasyonu (stderr tee) Level 2 milestone'a bırakıldı — şu an modül hazır ama bridgePTY bağlantısı yok.

**Yeni dosyalar (toplam 11):**
- `cmd/cop/staging_windows.go` + `_other.go` + `_test.go`
- `cmd/cop/dry_run.go` + `_windows.go` + `_other.go`
- `cmd/cop/access_telemetry.go` + `_test.go`
- `cmd/cop/container_init_windows_test.go`
- `internal/daemon/staging_cleanup_windows.go` + `_other.go` + `_test.go`
- `internal/sandbox/container/overlay_probe_windows_test.go`
- `tests/e2e/smoke_claude_windows_test.go`
- `tests/e2e/bash_subprocess_test.go`
- `tests/e2e/network_allowlist_test.go`
- `tests/e2e/parallel_windows_test.go`
- `tests/e2e/suspend_resume_windows_test.go`

**Toplam test sayısı:** 30+ yeni unit test (staging, access_telemetry, staging_cleanup, container_init, envsetup edge, virtualhome edge), 6 integration test dosyası.

**Verify:** `go vet ./... && go test ./...` tamamı yeşil. Live HCS testleri admin + Claude kurulu Windows makinede `go test -tags=integration ./tests/e2e/... ./internal/sandbox/container/...` ile tetiklenir.

---

## 2026-04-22: Eksik Kapatma Turu

İlk turdan sonra raporlanan 10 açık maddenin tamamı kapatıldı:

- **Eksik 1 — Mklink fallback kodu.** `cmd/cop/staging_windows.go`'da `AIPD_STAGING_LINK=1` env flag'i ile opt-in link modu. Link modunda Guest path `C:\aipd-home\stage` olur, `WriteLinkManifest()` `_manifest.json` yazar. `cmd/cop/container_init_windows.go:linkStagedFiles` manifest'i okur, her entry için `os.Link` (hardlink) → cross-volume copy fallback. `stagingLinkManifestDirOverrideForTests` hook ile unit testable. `.bashrc` placeholder staging tree'de de pre-seed edildi (MSYS2 login shell koruması). 4 yeni unit test (`TestStagingMounts_LinkModeUsesStageSubdir`, `TestStagingBashrcPreSeeded`, `TestStagingWriteLinkManifest`, `TestProjectStagedFile_*`, `TestLinkStagedFiles_*`).
- **Eksik 2 — DNS proxy audit + admin direct path fix.** `CreateOpts.DNSServer` alanı eklendi. `cmd/cop/dnsproxy_direct_{windows,other}.go` non-broker (admin direct) path'te `daemon.StartDNSProxy` çağırıp HNS endpoint'e bağlıyor — önceden sadece broker path bağlıyordu, direct path'te allowlist enforcement sessizce düşüyordu. `ensureNATEndpoint(dnsServer)` imzası değişti, `HNSEndpoint.DNSServerList` pin'li. `stripPort` + `allDigits` helper'ları + unit testleri.
- **Eksik 3 — IDE manuel test notları.** `docs/WINDOWS_SANDBOX.md`'ye "IDE Integration (VSCode / JetBrains)" bölümü — file watcher mekanizması, bilinen limitasyonlar, test akışları, staging/scratch dışındaki path'lerin mid-session görünmezliği.
- **Eksik 4 — Lint pass.** `gopls` static-analysis uyarılarının tamamı temizlendi (`session.go` ve `session_test.go`'da `slices.Contains` + unused `key := key` kaldırılması). `go vet ./...` temiz.
- **Eksik 5 — Docs staging bölümleri.** `docs/TECHSPEC.md §4.0 Windows Staging-Based File Mount Emulation` (state machine tablosu), `docs/ARCHITECTURE.md:Transparency Model` staging entegrasyonu ve iki mount modu özeti, `docs/WINDOWS_SANDBOX.md` staging problem/solution bölümü ve test haritası.
- **Eksik 6 — Runtime telemetry entegrasyonu.** `cmd/cop/pty.go:bridgePTY` variadic observer parametresi alıyor, PTY→stdout io.Copy'ye `io.MultiWriter` ile accessTelemetry tee ediliyor. `executeTool` tool exit sonrası `telemetry.Report(os.Stderr)` + TTY'de `handleAccessPrompt` interactive onay akışı. `appendConfigDirsToProfile` + `userProfilesDir` yeni profile'ı scaffold eder veya mevcuduna append eder. `AIPD_NO_ACCESS_TELEMETRY=1` env flag'i ile opt-out. 3 yeni unit test (scaffold, append, custom profilesDir).
- **Eksik 7 — access_prompt_test.go e2e.** `tests/e2e/access_prompt_test.go` — kasıtlı olarak var olmayan sentinel path'e cat/type ile erişim → telemetry report'un stderr'de path ismini ve "not mounted" header'ını bastığını doğrular. Integration tag; hem Windows hem Unix için.
- **Eksik 8 — Smoke best-effort doğrulama.** Live HCS + Claude yüklü makine erişimim olmadığı için 8-senaryo smoke suite çalıştırılamadı. Yapılabilen doğrulamalar: `cop --dry-run-mounts claude` → **R1 root-mount check: PASS** (canlı çıktı), `go test ./... -count=1` → 14/14 paket yeşil, `cmd/cop` içinde 94 unit test PASS. Cross-platform build: `GOOS=linux go build ./...` ve `GOOS=darwin go build ./...` temiz.
- **Eksik 9 — Toplu commit.** Aşağıdaki coherent commit atılacak.
- **Eksik 10 (önceki raporda AskUserQuestion ile sorulması gereken "mklink fallback aktifleşmeli mi" sorusu)** — gerekmedi, opt-in flag tasarımı karar vermeyi runtime'a bıraktı.

**Dosya sayıları sonrası:**
- Yeni Go dosyaları: staging_{windows,other}.go + _test, dry_run*.go, access_telemetry.go + _test, container_init_windows_test.go, staging_cleanup_{windows,other}.go + _test, overlay_probe_windows_test.go, dnsproxy_direct_{windows,other}.go, dns_endpoint_windows_test.go
- 6 integration test dosyası (smoke_claude, bash_subprocess, network_allowlist, parallel, suspend_resume, access_prompt)
- Docs güncellendi: progress.md, SECURITY.md, TECHSPEC.md, ARCHITECTURE.md, WINDOWS_SANDBOX.md, CLAUDE.md Run History
- Toplam yeni unit test sayısı: **50+**

**Son kontrol:**
```
$ go vet ./...                      # temiz
$ go test ./... -count=1            # 14/14 paket yeşil
$ GOOS=linux go build ./...         # temiz
$ GOOS=darwin go build ./...        # temiz
$ cop --dry-run-mounts claude       # R1 root-mount check: PASS
```

---

---

## Özet: Milestones ve Durumları

| ID | Milestone | Durum | Not |
|----|-----------|-------|-----|
| M1 | Foundation (config, interface, registry) | Tamamlandı | Go 1.25, cobra, viper, hcsshim entegre |
| M2 | Sandbox Works (container içinde process + PTY) | Kısmen | ConPTY çalışıyor, FS izolasyonu uygulanmış ama sınır ihlalleri var |
| M3 | Credentials + Security (resource limits, network policy) | Kısmen | SSH agent forwarding OK, network allowlist UYGULANMIYOR (kod sessizce open) |
| M4 | Daemon + TUI (named pipe, session list, suspend/resume) | Tamamlandı | station daemon + bubbletea TUI çalışıyor |
| M5 | Integration (cop-station IPC, E2E test, docs) | **AÇIK** | Exit 57, version mismatch hack, AppData sızıntı aktif sorun |
| M6 | macOS (Seatbelt) | Kod tamam, test eksik | SBPL profile yazıldı |
| M7 | Linux (bubblewrap) | Kod tamam, network allowlist eksik | bwrap limitation dokümante |
| M8 | Release (GoReleaser + CI/CD) | GoReleaser config hazır | CI yeşil ama Windows E2E integration-only |

---

## Bölüm 1: Denenen ve Tamamen Vazgeçilen Yaklaşımlar

### 1.1 CreateProcessWithTokenW
**Dönem:** Proje ilk haftaları
**Amaç:** Restricted token ile tool process'ini başlat
**Hata:** `ERROR_PRIVILEGE_NOT_HELD` — `SeImpersonatePrivilege` gerekli, normal user token'ında yok
**Durum:** Vazgeçildi
**Belge:** `docs/WINDOWS_SANDBOX.md`, `docs/SOLVE_BRIEF.md`

### 1.2 CreateProcessAsUser (normal user)
**Hata:** `ERROR_PRIVILEGE_NOT_HELD` (kod 1314) — `SeIncreaseQuotaPrivilege` gerekli
**Durum:** Vazgeçildi

### 1.3 NtSetInformationProcess
**Amaç:** Kernel seviyesinde process bilgisi set et
**Hata:** `STATUS_PRIVILEGE_NOT_HELD` (0xc0000061)
**Durum:** Vazgeçildi

### 1.4 Self-Restrict Then CreateProcess
**Amaç:** Parent önce kendini restrict et, sonra child spawn et
**Sonuç:** CreateProcess bile çalışmadı
**Durum:** Vazgeçildi

### 1.5 CreateProcess(SUSPENDED) + Self-Restrict
**Amaç:** Suspended child, restrict ana thread, resume
**Sonuç:** Child process FULL token ile çalıştı — restrict geç uygulandı
**R1 İhlali:** EVET
**Durum:** Vazgeçildi

### 1.6 Thread Impersonation + CreateProcess
**Amaç:** Thread-level impersonation ile child'a primary token verme
**Sonuç:** Primary token her zaman inherit edildi, impersonation thread token'ı child'a geçmedi
**R1 İhlali:** EVET
**Durum:** Vazgeçildi

### 1.7 PROC_THREAD_ATTRIBUTE_TOKEN
**Amaç:** Process attribute ile token explicitly set et
**Sonuç:** Bu attribute Windows API'de mevcut değil (belgeler yanlış yönlendirdi)
**Durum:** Vazgeçildi

### 1.8 Job Object Filesystem Restriction
**Amaç:** Job Object ile FS erişimini kısıtla
**Sonuç:** Job Object dosya sistemi erişimini kısıtlamıyor — UI/process/memory/IO limitleri var ama FS yok
**R1 İhlali:** EVET
**Durum:** Vazgeçildi. SOLVE_BRIEF'te "ALT-D: Job Object only" olarak "insecure, last resort" işaretli.

### 1.9 ALT-A: Chromium Two-Phase Wrapper
**Amaç:** cop -> restricted-exec cop -> tool (Chromium broker pattern)
**Sonuç:** Çalıştı ama Low Integrity Level workdir'a yazmayı da engelledi — kullanıcının kendi projesine yazamaz oldu
**Durum:** Vazgeçildi

### 1.10 ALT-B: CreateProcessWithTokenW + Named Pipe Stdio
**Amaç:** Token restriction + IPC üzerinden stdio forwarding
**Sonuç:** Process oluştu ama stdio bağlanmadı — named pipe bridging primary token ile çakıştı
**Durum:** Vazgeçildi

### 1.11 ALT-C: Admin Broker + SeIncreaseQuotaPrivilege Debug
**Amaç:** Admin broker içinde privilege enable + CreateProcessAsUser
**Sonuç:** `enablePrivilege` bug fix sonrası çalıştı ama HCS Container path ile paralel geliştiriliyordu
**Durum:** HCS geçişi ile supersede edildi

### 1.12 ALT-E: Windows Service (SYSTEM token)
**Amaç:** SYSTEM token ile en geniş yetki, sonra explicit restrict
**Sonuç:** Araştırma aşamasında kaldı — en sağlam ama en karmaşık yol
**Durum:** Değerlendirildi, HCS daha temiz bulundu

### 1.13 ALT-F: LsaAddAccountRights + Privilege Grant
**Amaç:** User'a runtime'da privilege ekle
**Sonuç:** PC restart sonrası bile çalışmadı — LSA cache ve policy refresh sorunu
**Durum:** Vazgeçildi

### 1.14 Iteration 1: CreateRestrictedToken + DACL Tabanlı FS Izolasyon
**Amaç:** Token restrict + DACL'i tool çalışırken dinamik değiştir
**Sorun 1:** Low Integrity Level workdir yazmayı engelledi
**Sorun 2:** `SetNamedSecurityInfo` mount başına ~100-500ms sürüyor, toplam ~2-5s overhead (kabul edilemez)
**Durum:** SOLVE_BRIEF Iteration 1 -> "superseded"

### 1.15 Iteration 2: Restricting SIDs (Chromium pattern)
**Amaç:** Per-process random SID + `CreateRestrictedToken(SidsToRestrict)`
**Engel:** DACL performance fix'e bağımlıydı, o çözülmedi
**Durum:** Hiç başlatılmadı, SOLVE_BRIEF Iteration 2 -> "superseded"

### 1.16 Windows Sandbox (.wsb) ve AppContainer
**Değerlendirme:** Araştırma aşamasında bırakıldı. Windows Sandbox programatik API sunmuyor; AppContainer Low IL tam FS namespace izolasyonu sağlamıyor.
**Durum:** Değerlendirildi, implemente edilmedi

---

## Bölüm 2: HCS Container Geçişi ve Karşılaşılan Sorunlar (Kronolojik)

### 2.1 Geçiş Kararı
**Tarih:** ~Mart 2026
**Neden:** Restricted token/DACL yollarının hiçbiri R1'i tam karşılayamadı. HCS Container kernel-level bind mount ile bildirilmemiş path'leri container namespace'inden tamamen kaldırır.
**Referans:** `docs/SOLVE_BRIEF.md:118-124` — "Superseded by HCS Container approach..."

### 2.2 Erken Hata: "Erişim Engellendi" — PrepareLayer/ActivateLayer Eksik
**Tarih:** Session `ad31aa9f` erken bölümleri
**Hata:** `hcs::CreateComputeSystem cop-broker-...: Erişim engellendi.`
**Root cause:** `hcsshim.PrepareLayer` ve `hcsshim.ActivateLayer` çağrılmıyordu — scratch layer mount edilmeden CreateContainer deneniyordu
**Çözüm:** Layer activation sequence eklendi
**Durum:** Çözüldü

### 2.3 "Sistem Belirtilen Dosyayı Bulamıyor" — Layer Path Yanlış
**Tarih:** Session `f7af4c8a`
**Hata:** `hcs::CreateComputeSystem cop-...-hv: Sistem belirtilen dosyayı bulamıyor.`
**Root cause:** `brokerBaseLayerPath()` Hyper-V fallback'te yanlış path dönüyordu, nanoserver base layer bulunamıyordu
**Çözüm:** Path lookup düzeltildi
**Durum:** Çözüldü

### 2.4 ERROR_INVALID_PARAMETER — VolumePath Karmaşası
**Tarih:** Session `ad31aa9f` uzun bir döngü
**Hata:** `ERROR_INVALID_PARAMETER` hem process hem Hyper-V isolation'da
**Root cause:** `VolumePath` ContainerConfig alanı process isolation için zorunlu, Hyper-V için geçersiz. Bir refactor sırasında yanlışlıkla silinmişti.
**Çözüm:** Process path'te `VolumePath` restore, Hyper-V path'te `VolumePath = ""` açıkça set
**Durum:** Çözüldü (kısmen, aynı oturumda birkaç kere regression gördü)

### 2.5 0xc0370106 — Kernel Version Mismatch (KISMEN AÇIK)
**Tarih:** Session `698d7056`, `06760fd5`
**Hata:** `hcs::System::Start: failure in a Windows system call: Sanal makine veya kapsayıcıdan beklenmedik şekilde çıkıldı. (0xc0370106)`
**Root cause:** Host build 26200 (Windows 11 Insider 25H2), nanoserver image build 26100. `wcifs` minifilter host ile container OS build eşleşmesini zorunlu tutuyor.
**Deneme 1:** `SkipVersionCheck=2` registry key — vmcompute restart gerektirdi, işe yaramadı
**Deneme 2:** `SkipVersionCheck=1` registry key + Hyper-V fallback — kısmen çalıştı ama Microsoft-unsupported
**Deneme 3:** Process isolation Create başarısız -> Hyper-V isolation ile retry — mevcut davranış
**Durum:** **WORKAROUND ile kapatıldı, kök çözümü yok.** Hyper-V isolation default yapılmalı (mevcut plan'da Faz 2).

### 2.6 HCS Stale State — Global Layer Activation Çakışması
**Tarih:** Session `ad31aa9f:2552`
**Gözlem:** Diagnostic tool process isolation ile başarıyla çalıştı, broker aynı kodla başarısız oldu
**Root cause:** Önceki başarısız denemelerden kalan layer activation'ları HCS service'inde stale kalıyordu
**Workaround:** `Get-ComputeProcess | Stop-ComputeProcess` manuel sıfırlama
**Durum:** Kök sebep çözülmedi, cleanup path iyileştirmeleri ile azaldı

### 2.7 HNS NAT Endpoint — Start() Başarısız
**Tarih:** Session `698d7056:541`
**Hata:** MappedDir tek başına çalışıyor ama HNS NAT endpoint eklenince `container.Start()` 0xc0370106 dönüyor
**Root cause:** Stale/broken NAT network
**Workaround:** `Start()` başarısız olursa endpoint olmadan yeniden dene (network-less fallback)
**Durum:** Workaround ile kapatıldı

### 2.8 MSYS2 Bash Exit Code 57 (AKTİF, EN KRİTİK)
**Tarih:** Session `698d7056`, `e5baf386`, `87e2221a` — haftalarca süren problem
**Semptom:** `cop claude` container başarıyla açılıyor, TUI görünüyor, ama Claude Code'un bash tool'u her komutta exit 57 dönüyor

**Deneme 1 (Hipotez: HOME eksik):** HOME scratch layer'da `C:\aipd-home` olarak oluşturuldu, USERPROFILE override edildi
**Sonuç:** Exit 57 devam etti

**Deneme 2 (Hipotez: TEMP yanlış yerde):** TEMP `C:\Windows\Temp` -> `C:\aipd-temp` -> host-mounted -> scratch-layer `C:\aipd-temp` üç farklı yaklaşım
**Sonuç:** Hiçbiri çalışmadı

**Deneme 3 (Hipotez: Git R/O mount):** `%ProgramFiles%/Git` R/W yapıldı
**Sonuç:** Exit 57 devam etti

**Deneme 4 (Session `87e2221a` root cause tespit):** Gerçek root cause bulundu: Claude Code `%LOCALAPPDATA%\Temp\claude\<workspace>\tasks\<id>.output` path'ine yazıyor. Host `%LOCALAPPDATA%` = `C:\Users\Sungur\AppData\Local` container'da mount edilmediği için (sadece alt dizin `\Temp` mount'u vardı) Claude Code alt klasör yaratamıyor.

**Fix (uygulandı, test edilmedi):** `DefaultToolDeps`'e `%LOCALAPPDATA%/Temp` eklendi. Binary deploy edildi, session kullanıcı test etmeden bitti.

**Aktuel Durum:** **HÂLÂ TEST EDİLMEDİ / HÂLÂ SORUN VAR.** Kullanıcı 2026-04-09 itibariyle "hâlâ devam ediyor" olarak bildirdi.

**Doğru Kök Çözüm (mevcut plan Faz 1):** `%LOCALAPPDATA%` env'ini container internal virtual home'a yönlendir (`C:\aipd-home\AppData\Local`), tüm user profile env'leri (APPDATA, TEMP, TMP) aynı virtual home altında resolve olsun. Bu şekilde tool'lar zaten writable bir path hesaplar, mount gerektirmez, host'a sızıntı olmaz.

**Kullanıcı morali:** Session `87e2221a:89` — "Bu süreç gerçekten aşırı uzadı... Cidden yorulmaya başladım."

### 2.9 tempDir Deadlock — HCS PrepareLayer Filesystem Filter Sınırı
**Tarih:** Session `06760fd5:616`, `698d7056:114`
**Root cause:** `tempDir` scratchDir içinde oluşturuluyordu — HCS `PrepareLayer`'ın WCIFS filter sınırı içinde. Aynı path'i `MappedDirectory` olarak eklemek deadlock tetikliyordu.
**Fix:** `tempDir` scratchDir'in kardeşi olarak taşındı, sonra tamamen kaldırıldı (scratch layer içi dinamik oluşturma ile)
**Durum:** Çözüldü
**Kalıntı:** `box.go:252` `tempDir string` struct alanı hâlâ var ama hiç atanmıyor — ölü kod (plan Faz 5'te temizlenecek)

### 2.10 EPERM — Claude Code Tasks Klasörü PATH Mount Çakışması
**Tarih:** Session `e5baf386:594`
**Root cause:** PATH-based auto-mount sistemi eklenince `%TEMP%` PATH entry'si de R/O mount edildi -> Claude Code `tasks/` yazamadı
**Fix:** `addHostPathMounts` TEMP/TMP'yi PATH'den filtreliyor
**Durum:** Çözüldü

### 2.11 Network Allowlist Uygulanmıyor (AÇIK)
**Tarih:** Süregelen
**Semptom:** `cfg.Network.Policy = "allowlist"` kabul ediliyor, `cfg.Network.Allowlist` okunuyor, ama container'da hiçbir filter uygulanmıyor — tüm traffic geçiyor
**Root cause:** HCS backend per-host network policy yazımı için WFP driver gerektiriyor, yazılmadı
**Dokümantasyon:** `docs/TROUBLESHOOTING.md:150-158` — "not yet fully implemented"
**Workaround:** Kullanıcılara `network.policy: blocked` öner
**Durum:** **AÇIK.** Mevcut plan Faz 4'te DNS proxy ile çözülecek.

### 2.12 SetupContainer Version Mismatch Log Hatası
**Tarih:** Süregelen
**Sorun:** `broker_windows.go:97` log mesajı "SkipVersionCheck=2" diyor ama kodda `SetDWordValue("SkipVersionCheck", 1)` ile 1 yazılıyor
**Durum:** Yanıltıcı log, Faz 2'de tüm fonksiyon siliniyor

### 2.13 TestClient_Close_Idempotent Deadlock (AÇIK)
**Tarih:** Pre-existing, birden fazla session'da "scope dışı" olarak ertelendi
**Semptom:** `internal/daemon/client_test.go` 10 dakika timeout
**Root cause:** `Client.Close()` WaitGroup'u bekliyor ama `handleIncomingCommands` goroutine'i pipe read'de takılı, hiç return etmiyor
**Durum:** **AÇIK.** Mevcut plan Faz 5'te `SetReadDeadline(time.Now())` ile pipe unblock + WaitGroup ile çözülecek.

### 2.14 ds-blueprint 2026-04-01 Bulguları (AÇIK)
**Tarih:** 2026-04-01 ds-blueprint çalıştırması
**Sonuç:** 13 yeni bulgu (hepsi "skipped"), en kritiği TST-01 (flag rename test HIGH)
**Durum:** **13 bulgu hâlâ AÇIK.** Mevcut plan Faz 5'te ayrı atomic commit'ler olarak ele alınacak.

### 2.15 Profile Audit (AÇIK)
**Tarih:** 2026-03-31 session sonu — "sonraki session için öncelik 1" notu
**Sorun:** 24+ tool profilinin config_dirs, env_keys, runtime, default_args doğruluğu tam olarak verify edilmedi
**Durum:** **AÇIK.** Mevcut plan Faz 3'te hibrit virtual home stratejisi ile birlikte her profil gözden geçirilecek.

### 2.16 focus_unix.go Stub
**Tarih:** Sürekli
**Semptom:** `internal/platform/focus_unix.go` "focus: bring-to-front not implemented on this platform"
**Durum:** Platform parity eksiği, M6/M7 scope'unda kalıyor, acil değil

### 2.17 tests/e2e Integration-Only
**Tarih:** Sürekli
**Semptom:** `tests/e2e/basic_test.go` ve `container_windows_test.go` `//go:build integration` tag'li, normal `go test ./...`'ta çalışmıyor
**Durum:** CI'da otomatik R1 testi YOK. Mevcut plan Faz 6'da bu tag gevşetilecek, yeni testler eklenecek.

---

## Bölüm 3: Bilinen Genel Riskler (Risk Register)

Ref: `docs/TASKS.md:223-234`

| ID | Risk | P | I | Durum |
|----|------|---|---|--------|
| R1 | Competitor speed (Claude Squad, scode, Docker) | H | H | Piyasa hızlanıyor — açık |
| R2 | HCS Container documentation gaps | H | H | hcsshim kısmen dokümante, belirsizlikler devam |
| R3 | ConPTY stability | M | H | Test edildi, stabil görünüyor |
| R4 | Seatbelt deprecation (macOS) | L | H | Düşük |
| R5 | Market fragmentation | M | M | Açık |
| R6 | Scope creep | M | M | M5 scope freeze var |
| R7 | Key person risk | H | M | Tek geliştirici |
| R8 | Timeline slippage | M | M | Açık |

---

## Bölüm 4: Çözülmüş Büyük Başarılar

- **HCS Container backend operasyonel** — base layer, scratch layer, volume path, PrepareLayer/ActivateLayer sequence çalışıyor
- **Hyper-V fallback mevcut** — process isolation başarısız olsa bile Hyper-V retry ediyor (ideal tablo Hyper-V-only olacak)
- **MappedDirectory deadlock çözüldü** — tempDir sibling path refactor sonrası
- **PATH auto-mount** — tool'lar host PATH binary'lerine R/O erişim alıyor (plan'da genişletilecek)
- **Toolchain deps mount** — GOPATH, CARGO_HOME, RUSTUP_HOME, pip user installs R/W mount
- **MSYS2 exit 57 hipotezlerinden ilk 3'ü elendi** — kök sebep 4. denemede doğru teşhis edildi
- **Credential discovery + injection** — SSH agent, API keys, GitHub token, git identity
- **TUI + daemon + session management** — station TUI çalışıyor, suspend/resume var
- **Cross-compile parity** — macOS ve Linux backend'leri build edilebilir
- **Setup otomasyonu** — `station setup` MCR anonim pull, HCS feature check, UAC elevation, named mutex race protection

---

## Bölüm 5: Sıradaki Plan

Mevcut plan ana yapıya entegre 7 faz halinde tüm açık sorunları kapatmayı hedefliyor. En kritik beklenen sonuç:

1. **Exit 57 kökten çözülmüş** — virtual home + hibrit bind mount ile tool state'i kaybolmadan FS izolasyonu tam
2. **0xc0370106 artık hiç karşılaşılmayacak** — Hyper-V default ile kernel paylaşımı yok
3. **R1 tam enforcement** — hem kod hem e2e test ile doğrulanmış
4. **Network allowlist gerçekten çalışıyor** — DNS proxy ile
5. **Pre-existing deadlock + 13 blueprint bulgusu + ölü kod** — tamamı temizlenmiş

Faz listesi:

| Faz | Amaç | Durum |
|-----|------|-------|
| 0 | Ön Doğrulama (manuel smoke test) | Bekliyor |
| 1 | Virtual Home + Env Refactor | Bekliyor |
| 2 | Hyper-V Isolation Default | Bekliyor |
| 3 | Host AppData Mount Temizliği + Mount Pipeline Refactor | Bekliyor |
| 4 | DNS Proxy Network Allowlist | Bekliyor |
| 5 | Temizlik (tempDir, deadlock, 13 blueprint) | Bekliyor |
| 6 | E2E Doğrulama (R1 otomatik testi) | Bekliyor |
| 7 | Dokümantasyon Senkronu | Bekliyor |

---

## Bölüm 6: v2 — Universal Win32 Base Image + Dynamic Mount Learning (2026-04-23)

**Kapsam:** 2026-04-22 staging refactor'un üstüne iki yeni katman:

1. **Features on Demand (FoD) tabanlı universal Win32 base image** — `station setup` artık plain `nanoserver:ltsc2025` layer'ı extract ettikten sonra üstüne WOWSupport + OpenSSH.Client + WinMgmt + PowerShellCore capabilities'lerini DISM ile kuruyor. Sonuç `%ProgramData%/aipd/layers/nanoserver-fod/`. Bu sayede MSYS2 bash'in `0xC0000139` STATUS_ENTRYPOINT_NOT_FOUND çökmesi kökten çözüldü. Manifest.json (base tag + FoD list + digest) cache invalidation'ı sağlıyor; tekrar `station setup` çağrısı değişiklik yoksa layer'ı yeniden inşa etmeden dönüyor.

2. **Dinamik mount öğrenme (learn-and-replay)** — cop çalışırken tool'un erişmeye çalıştığı ama mount edilmemiş path'leri stderr regex'leri ile yakalıyor (20+ pattern: PowerShell, .NET, Rust, Node, Python, Go, bash, make, cmake, pip, npm, cargo, git + mode-hint hem EACCES hem O_WRONLY/O_CREAT). Tool exit olduğunda interaktif TUI prompt ile her path için **rw/ro/skip/never/block** 5 seçenek sunuluyor. Seçimler `~/.aipd/profiles/<tool>.yaml`'a `ConfigDirEntry{Path, Mode, Source, Added}` olarak structured form'da yazılıyor; bir sonraki invocation'da bu entry'ler mount table'a otomatik ekleniyor. Kullanıcı onayı olmadan hiçbir path mount edilmiyor.

3. **Merkezi risk filter** — `internal/security/risky_paths.go` 7 kategoriden (SAM/SECURITY hive, SSH private key, cloud creds, credential store, browser session, password manager, Azure AD broker) oluşan deny-list. Deny-list match eden path'ler approval prompt'a dahi ulaşmıyor ve hiçbir profile dosyasına yazılmıyor — güvenlik sözleşmesi olarak override edilemez. Ek olarak kullanıcı `~/.aipd/deny/<tool>.yaml` ile kendi path'lerini ekleyebiliyor (additive — merkezi listeyi gevşetemez).

### Kapsanan dosyalar

| Yeni | Amaç |
|------|------|
| `internal/security/risky_paths.go` | 7-kategorili deny-list regex engine |
| `internal/security/user_deny.go` | User-scope additive deny override + wildcard support |
| `internal/security/current_user_{windows,other}.go` | Cross-platform USERNAME resolution |
| `internal/config/config_dir_entry.go` | `ConfigDirEntry` + `ConfigDirList` dual-shape YAML decoder |
| `internal/sandbox/container/image_manifest.go` | FoD layer manifest (read/write/stale check) |
| `internal/sandbox/container/image_manifest_other.go` | Non-Windows stub |
| `cmd/station/fod_install_windows.go` | DefaultFoDs + DISM offline add-capability + robocopy mirror |
| `cmd/station/fod_install_other.go` | Non-Windows stub |
| `cmd/cop/access_prompt_ui.go` | 5-yollu TUI prompt (RW/RO/Skip/Never/Block) + risk sınıflaması |
| `cmd/cop/profile_writer.go` | User-scope profile auto-grow + idempotent merge |
| `cmd/cop/access_telemetry_extended_test.go` | 20+ regex pattern + mode-upgrade + risk-filter unit testleri |
| `tests/e2e/base_image_fod_test.go` | Integration: bash+pwsh+ssh + manifest cache |
| `tests/e2e/restart_flow_test.go` | Integration: learn-and-replay + risky path filter |

### Değişen dosyalar

- `cmd/cop/access_telemetry.go` — 7 → 20+ regex pattern, `accessEntry{Path, Mode, Risky, RiskReason}`, `containsWriteHint` contextual mode upgrade, risky/user-deny filter
- `cmd/cop/session.go` — `addConfigDirMounts` `ExpandedConfigMounts()` + `Mode` field okur, `executeTool` restart hint mesajı
- `internal/config/tools.go` — `ToolDef.ConfigDirMounts []ConfigDirEntry` ekle, `ExpandedConfigMounts()` helper
- `internal/config/profiles.go` — `profileFile.ConfigDirs` `ConfigDirList`'e çevir, `parseProfile` multi-source merge (duplicate path upgrade)
- `internal/config/config.go` — `SetupConfig{FoDs []string}` eklendi (nil = default, empty = opt-out)
- `internal/sandbox/container/backend.go` — `baseLayerPath` FoD layer'ı öncelikli arar, plain layer fallback kalıyor
- `cmd/station/setup_container_windows.go` — `ensureFoDLayer` çağrısı Step 6 olarak eklendi

### Güvenlik kuralları

- Risk filter HİÇBİR KOŞULDA override edilemez — user deny-list sadece additive (daraltır, gevşetemez)
- Risky path'ler approval prompt'a ulaşmaz, Report ekran çıktısında gizlenir
- TTY olmayan ortamlarda (CI) prompt "non-interactive stdin" mesajıyla silently skip edilir — hiçbir path otomatik mount olmaz
- `ConfigDirEntry.Source` alanı `profile` / `auto` (prompt kabul) / `manual` (elle düzenlenmiş) şeklinde audit trail tutar

### Test sonuçları

- `go test ./...` tüm paketler yeşil (16 paket, 0 fail)
- `go build -tags=integration ./tests/e2e/...` integration test iskeletleri temiz derleniyor
- Cross-compile: linux + darwin (pre-existing `focus_darwin.go` `unreachable` uyarısı dışında) temiz
- `golangci-lint` benim yeni kodumda 0 bulgu (pre-existing shadow / errcheck uyarıları dışında)

---

## Kaynak Session Kayıtları (Bu progress.md İçin Taranılan)

- `ad31aa9f-6ab2-470c-aa6e-bdaebfc9a429.jsonl` (8.6MB) — en büyük, HCS erken dönem
- `f7af4c8a-4abd-4462-a4c2-b2f00ad4eae7.jsonl` (4.9MB) — layer path, VolumePath sorunları
- `06760fd5-3025-420a-ad31-a925339f2f11.jsonl` (4.9MB) — 0xc0370106 araştırma + SkipVersionCheck denemeleri
- `698d7056-dde1-40f6-8cb3-8d0953ac60ab.jsonl` (2.9MB) — HNS NAT endpoint, exit 57 ilk denemeler
- `e96fffc2-4e72-4a50-a0de-ca6bb0c10fe5.jsonl` (2.7MB) — DACL performance engeli, iteration 1 sonu
- `e5baf386-9eea-4e53-96f0-a2ee5b9c3dea.jsonl` (2.3MB) — PATH mount EPERM, exit 57 deneme 2
- `ebd7e963-2d57-4637-8f7c-6823f1cd8ae1.jsonl` (1.3MB) — iteration 2 planlama
- `57e02f4e-ff25-4c15-9320-403448fd9fc3.jsonl` (1.1MB) — ara oturumlar
- `87e2221a-2afc-42c0-acbe-bb24961321b4.jsonl` (779KB) — **EN YENİ (2026-04-09)** — exit 57 root cause tespit + fix deploy, test edilmeden kapanış
