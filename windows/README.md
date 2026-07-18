# Windows MSI Installer (scaffolding)

This directory contains the WiX v4 source for the production Windows
MSI. It is **scaffolding** — the build pipeline that ties it together
with code-signing and GoReleaser is not yet wired into CI.

## Files

- `dizgin.wxs` — WiX v4 source. Defines install layout, PATH entry,
  ProgramData ACLs, scheduled task wiring.
- `dizgind-prewarm.xml` — Scheduled Task definition for the dizgind
  daemon prewarm (Phase 1 plan, item A6).

## Build prerequisites

```powershell
# WiX v4 toolchain (one-time)
dotnet tool install --global wix

# Fresh dizgin binaries
make build
```

## Local build

From the repo root:

```powershell
wix build windows\dizgin.wxs `
  -d Version=1.0.0 `
  -d BinDir=bin `
  -arch x64 `
  -o dist\dizgin-windows-amd64.msi
```

## Code signing

EV cert is the long-lead item (Phase 1 plan, item F1 — 1-5 business
days for procurement). Once available:

```powershell
signtool sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 /a `
  dist\dizgin-windows-amd64.msi
```

For interim CI builds, **Azure Trusted Signing** is the cloud-native
fallback:

```powershell
azuresigntool sign `
  -kvu https://dizgin-signing.vault.azure.net `
  -kvi $env:AZURE_CLIENT_ID `
  -kvs $env:AZURE_CLIENT_SECRET `
  -kvc dizgin-prod-cert `
  -tr http://timestamp.acs.microsoft.com `
  -td sha256 `
  dist\dizgin-windows-amd64.msi
```

## TODO before first signed release

- [ ] Procure EV cert (F1 blocker; Azure Trusted Signing fallback OK).
- [ ] Wire `wix build` + `signtool sign` into a GoReleaser
      `builds.hooks.post:` stanza.
- [ ] Add MSI asset to the GitHub release manifest (cosign sign-blob
      + SBOM as for tar/zip artifacts; see `.goreleaser.yml`).
- [ ] Smoke-test install + uninstall on a clean Windows 11 VM:
      verify PATH gets dizgin.exe + dizgind.exe, scheduled task fires
      at next logon, uninstall removes both.
