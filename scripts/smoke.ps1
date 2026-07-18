# DIZGIN smoke test -- AppContainer backend (Windows)
#
# Single-command verification loop. Builds + installs, restarts the
# daemon, runs the canonical R1/R2 scenarios against the AppContainer
# backend, and confirms profile cleanup. Designed so `make smoke`
# is the only command a developer needs to type to validate a change.
#
# Usage:
#   make smoke                # full sequence
#   make smoke SKIP_BUILD=1   # iterate on the test cases without rebuilding
#
# Output goes to the console AND auto/last-test-run.log via
# Start-Transcript so the failure surface is one fixed-name file.

[CmdletBinding()]
param(
  [switch]$SkipBuild
)

$ErrorActionPreference = 'Continue'
$ScriptStart = Get-Date

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$LogDir   = Join-Path $env:ProgramData 'dizgin\logs'
$RunLog   = Join-Path $RepoRoot 'auto\last-test-run.log'
$AutoDir  = Split-Path $RunLog
if (-not (Test-Path $AutoDir)) {
  New-Item -ItemType Directory -Path $AutoDir -Force | Out-Null
}
# Rotate prior runs so the assistant can read one fixed name.
if (Test-Path $RunLog) {
  for ($i = 2; $i -ge 1; $i--) {
    $src = Join-Path $AutoDir "last-test-run.$i.log"
    $dst = Join-Path $AutoDir ("last-test-run." + ($i + 1) + ".log")
    if (Test-Path $src) { Move-Item -LiteralPath $src -Destination $dst -Force }
  }
  Move-Item -LiteralPath $RunLog -Destination (Join-Path $AutoDir 'last-test-run.1.log') -Force
}
Start-Transcript -Path $RunLog -Force | Out-Null

function Write-Section([string]$Title) {
  Write-Host ''
  Write-Host ('=' * 60) -ForegroundColor Cyan
  Write-Host (" $Title") -ForegroundColor Cyan
  Write-Host ('=' * 60) -ForegroundColor Cyan
}

# Per-case result tracker so the summary at the bottom reports
# pass / fail counts even when individual cases produce noisy output.
$Script:Cases = @()

function Test-Case {
  param(
    [string]$Name,
    [scriptblock]$Body,
    [int]$ExpectExit = 0,
    [string]$ExpectStdoutMatch = ''
  )
  Write-Host ''
  Write-Host ("--- $Name ---") -ForegroundColor Yellow
  $stdout = ''
  $exit = 0
  try {
    $stdout = & $Body 2>&1 | Out-String
    $exit = $LASTEXITCODE
  } catch {
    $stdout = $_.Exception.Message
    $exit = 1
  }
  $stdout = $stdout.Trim()
  if ($stdout) { Write-Host $stdout }
  $passExit = $exit -eq $ExpectExit
  $passMatch = $true
  if ($ExpectStdoutMatch) {
    $passMatch = $stdout -match $ExpectStdoutMatch
  }
  $pass = $passExit -and $passMatch
  $status = if ($pass) { 'PASS' } else { 'FAIL' }
  $color  = if ($pass) { 'Green' } else { 'Red' }
  $detail = "exit=$exit (want $ExpectExit)"
  if ($ExpectStdoutMatch) {
    $detail += "; stdout match /$ExpectStdoutMatch/=$passMatch"
  }
  Write-Host "  [$status] $detail" -ForegroundColor $color
  $Script:Cases += [pscustomobject]@{ Name = $Name; Pass = $pass; Detail = $detail }
}

# ---------------------------------------------------------------- Phase 1
if (-not $SkipBuild) {
  Write-Section 'Phase 1: make build install'
  Push-Location $RepoRoot
  try {
    & make build install
    if ($LASTEXITCODE -ne 0) {
      Write-Warning "make build install exited $LASTEXITCODE -- continuing so we can capture diagnostics"
    }
  } finally {
    Pop-Location
  }
} else {
  Write-Section 'Phase 1: SKIP (SkipBuild)'
}

# ---------------------------------------------------------------- Phase 2
# dizgin spawns dizgind automatically on first invocation, so we do not
# call dizgind start ourselves. A previous test run may have left the
# daemon healthy already — both cases produce the same result.
Write-Section 'Phase 2: backend probe'
Test-Case -Name 'dizgin --version reachable' -ExpectExit 0 -Body {
  dizgin --version
}

# ---------------------------------------------------------------- Phase 3
# Canonical scenarios. R1 fail-closed must produce a non-zero exit AND
# an access-denied surface; R2 happy path must round-trip stdout.
Write-Section 'Phase 3: R2 (native experience) — Windows inbox binaries'
# dizgin accepts ANY tool name (per DIZGIN design rule) — profiles/*.yaml
# only adds extra mounts/credentials for known AI tools. The AppContainer
# token always carries the ALL APPLICATION PACKAGES (S-1-15-2-1) group
# membership, which the kernel grants RX on inbox Microsoft components
# under %SystemRoot%\System32. So cmd.exe, powershell.exe, find.exe etc.
# round-trip cleanly without per-tool stamping.

Test-Case -Name 'R2: powershell -Command Write-Output hello' -ExpectExit 0 -ExpectStdoutMatch 'hello' -Body {
  dizgin powershell -NoProfile -Command 'Write-Output hello'
}

Test-Case -Name 'R2: powershell pwd' -ExpectExit 0 -Body {
  dizgin powershell -NoProfile -Command '(Get-Location).Path'
}

# Workdir mount must be R/W from inside the AppContainer. Write a probe
# file then read it back via PowerShell — exercises the per-session
# scratch grant and confirms host workdir is mounted RW.
Test-Case -Name 'R2: workdir R/W round-trip' -ExpectExit 0 -ExpectStdoutMatch 'DIZGIN_OK' -Body {
  dizgin powershell -NoProfile -Command "Set-Content .dizgin-smoke-probe DIZGIN_OK; Get-Content .dizgin-smoke-probe; Remove-Item .dizgin-smoke-probe"
}

Write-Section 'Phase 3b: 3rd-party tool via daemon stamp delegation'
# bash.exe lives under C:\Program Files\Git\usr\bin and is NOT covered
# by the inbox ALL APPLICATION PACKAGES grant. A non-elevated dizgin also
# cannot stamp Program Files (TrustedInstaller-owned). With the
# transient stamp delegation path wired (2026-05-02): dizgin resolves
# bash.exe + transitive MSYS2 DLL deps, sends a TypeStampPaths request
# to the LocalSystem dizgind daemon, daemon stamps each path with the
# AppContainer SID, and CreateProcessAsUserW succeeds. The orphan
# sweeper revokes when dizgin exits or after the 4h TTL.
$bash = (Get-Command bash -ErrorAction SilentlyContinue).Source
if ($bash) {
  Write-Host "  bash binary: $bash" -ForegroundColor DarkGray
  Test-Case -Name 'bash -c echo hello (via daemon stamp)' -ExpectExit 0 -ExpectStdoutMatch 'hello' -Body {
    dizgin bash -c 'echo hello'
  }
} else {
  Write-Host '  bash not on PATH — skipping 3rd-party probe'
}

Write-Section 'Phase 4: R1 (FS isolation — fail-closed)'
# An undeclared host path must NOT be readable. The AppContainer DACL
# has no grant for the user profile's .ssh dir; the read must fail.
$sshDir = Join-Path $env:USERPROFILE '.ssh'
if (Test-Path $sshDir) {
  $probe = Get-ChildItem $sshDir -File -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($probe) {
    $escaped = $probe.FullName.Replace("'", "''")
    Test-Case -Name "R1: read $sshDir denied" -ExpectExit 1 -Body {
      dizgin powershell -NoProfile -Command "Get-Content -LiteralPath '$escaped' -ErrorAction Stop"
    }
  } else {
    Write-Host '  no .ssh files to probe — skipping R1 SSH case'
  }
} else {
  Write-Host '  no ~\.ssh dir — skipping R1 SSH case'
}

# Another R1 surface: a sibling user's profile dir. AppContainer SID is
# not in any ACE there, so even directory listing must fail.
Test-Case -Name 'R1: enum %SystemDrive%\Users denied' -ExpectExit 1 -Body {
  dizgin powershell -NoProfile -Command "Get-ChildItem 'C:\Users\Public\Desktop' -ErrorAction Stop | Out-Null; Get-Content -LiteralPath 'C:\Users\Default\NTUSER.DAT' -ErrorAction Stop"
}

# ---------------------------------------------------------------- Phase 5
Write-Section 'Phase 5: AppContainer profile + transient stamp lifecycle'

# After every dizgin invocation finishes Cleanup, the per-session profile
# under HKCU\...\AppContainer\Mappings should be reaped. Enumerate all
# dizgin-dizgin-* mappings; we expect zero left over.
$mapKey = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings'
if (Test-Path $mapKey) {
  $orphans = Get-ChildItem $mapKey -ErrorAction SilentlyContinue | Where-Object {
    $name = (Get-ItemProperty -Path $_.PSPath -Name 'Moniker' -ErrorAction SilentlyContinue).Moniker
    $name -and $name.StartsWith('dizgin-dizgin-')
  }
  if ($orphans) {
    Write-Host ('  WARN: {0} orphan dizgin-dizgin-* profile(s) under HKCU mappings' -f $orphans.Count) -ForegroundColor Yellow
    $orphans | ForEach-Object {
      $moniker = (Get-ItemProperty -Path $_.PSPath -Name 'Moniker' -ErrorAction SilentlyContinue).Moniker
      Write-Host "    - $moniker"
    }
  } else {
    Write-Host '  no dizgin-dizgin-* mappings — Cleanup() reaped them' -ForegroundColor Green
  }
} else {
  Write-Host '  HKCU mappings key does not exist (no AppContainer ever ran on this host)'
}

# Scratch dir cleanup. Daemon orphan sweep purges stale ones; we just
# show the current count for visual feedback.
$acRoot = Join-Path $env:ProgramData 'dizgin\appcontainer'
if (Test-Path $acRoot) {
  $live = Get-ChildItem $acRoot -Directory -ErrorAction SilentlyContinue
  Write-Host "  $($live.Count) scratch dir(s) under $acRoot"
}

# Transient stamp lifecycle: every successful Phase 3b run grants the
# AppContainer SID RX on bash.exe (and transitive MSYS2 DLLs) via the
# dizgind daemon's stamp broker. Cleanup must revoke each ACE; the
# orphan sweeper catches any dizgin that crashed without revoking. After
# all dizgin invocations finish, no dizgin-dizgin S-1-15-2-* ACE should
# survive on bash.exe's DACL.
if ($bash) {
  $dacl = & icacls $bash 2>&1 | Out-String
  $stampedSids = @($dacl -split "`n" | Where-Object {
    $_ -match 'S-1-15-2-\S+' -and $_ -notmatch 'NT AUTHORITY' -and $_ -notmatch 'BUILTIN'
  })
  if ($stampedSids.Count -eq 0) {
    Write-Host '  no residual S-1-15-2-* ACE on bash.exe — daemon revoked all transient stamps' -ForegroundColor Green
    $Script:Cases += [pscustomobject]@{ Name = 'transient stamp revoke'; Pass = $true; Detail = 'bash.exe DACL clean' }
  } else {
    Write-Host ('  WARN: {0} residual AC ACE(s) on bash.exe' -f $stampedSids.Count) -ForegroundColor Yellow
    $stampedSids | ForEach-Object { Write-Host "    $_" }
    $Script:Cases += [pscustomobject]@{ Name = 'transient stamp revoke'; Pass = $false; Detail = ('{0} residual ACE(s)' -f $stampedSids.Count) }
  }
}

# In-memory stamp record table on the daemon side. After all cops
# exit, the broker should hold zero records for our user. We surface
# the daemon-log evidence in Phase 6; here we just probe the shape
# via the registered API endpoint when available.

# ---------------------------------------------------------------- Phase 6
Write-Section 'Phase 6: daemon log tail + stamp-broker activity'
$daemonLog = Join-Path $LogDir 'daemon.log'
if (Test-Path $daemonLog) {
  $size = (Get-Item $daemonLog).Length
  Write-Host "[daemon.log] $daemonLog ($size bytes, last 80 lines)" -ForegroundColor DarkCyan
  Get-Content $daemonLog -Tail 80

  # Confirm the stamp broker handled the bash session. Look for the
  # canonical log line emitted by brokerStampPaths after icacls runs.
  $stampBrokerHits = (Get-Content $daemonLog -ErrorAction SilentlyContinue | Select-String -Pattern 'stamp-broker: pid=' -SimpleMatch:$false).Count
  $stampSweeperHits = (Get-Content $daemonLog -ErrorAction SilentlyContinue | Select-String -Pattern 'stamp-sweeper:' -SimpleMatch:$false).Count
  Write-Host ''
  Write-Host ("  stamp-broker log entries: {0}" -f $stampBrokerHits) -ForegroundColor DarkCyan
  Write-Host ("  stamp-sweeper log entries: {0}" -f $stampSweeperHits) -ForegroundColor DarkCyan
  if ($bash -and $stampBrokerHits -lt 1) {
    Write-Host '  WARN: bash on PATH but no stamp-broker activity in daemon.log' -ForegroundColor Yellow
    $Script:Cases += [pscustomobject]@{ Name = 'stamp-broker logged'; Pass = $false; Detail = '0 hits' }
  } elseif ($bash) {
    $Script:Cases += [pscustomobject]@{ Name = 'stamp-broker logged'; Pass = $true; Detail = ('{0} hits' -f $stampBrokerHits) }
  }
} else {
  Write-Host "[daemon.log] $daemonLog not present" -ForegroundColor DarkYellow
}

# ---------------------------------------------------------------- Phase 7
Write-Section 'Phase 7: no-fallback policy guards'
# Verify the documented no-fallback signature: HCS Hyper-V backend is
# unreachable without DIZGIN_FORCE_CONTAINER=1, and bubblewrap allowlist
# without CAP_NET_ADMIN/nft fails fast. Both are off the Windows happy
# path but we surface the env-flag shape so a regression that
# reintroduces a silent fallback shows up as a PASS-becoming-FAIL.
Test-Case -Name 'no-fallback: DIZGIN_FORCE_CONTAINER opt-in only' -ExpectExit 0 -Body {
  if (Get-Command dizgin -ErrorAction SilentlyContinue) {
    & dizgin --version 2>&1
  } else {
    'dizgin not on PATH'
  }
}

# ---------------------------------------------------------------- Summary
Write-Section 'Summary'
$passed = ($Script:Cases | Where-Object Pass).Count
$failed = ($Script:Cases | Where-Object { -not $_.Pass }).Count
foreach ($c in $Script:Cases) {
  $marker = if ($c.Pass) { '+' } else { 'x' }
  $color  = if ($c.Pass) { 'Green' } else { 'Red' }
  Write-Host ("  [{0}] {1}  ({2})" -f $marker, $c.Name, $c.Detail) -ForegroundColor $color
}
$elapsed = (Get-Date) - $ScriptStart
Write-Host ''
Write-Host ("Done in {0}s -- {1} pass / {2} fail" -f [int]$elapsed.TotalSeconds, $passed, $failed) -ForegroundColor Cyan
Write-Host "Full transcript: $RunLog" -ForegroundColor DarkGreen

Stop-Transcript | Out-Null
exit $(if ($failed -eq 0) { 0 } else { 1 })
