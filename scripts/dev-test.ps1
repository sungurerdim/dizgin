# DIZGIN developer test loop -- Windows
#
# One-shot script for the inner loop while debugging the runhcs
# delegation path. Build + install + run a test command + dump every
# log we have on disk so the failure can be triaged without re-typing
# the same five commands every iteration.
#
# Usage examples:
#   .\scripts\dev-test.ps1                              # echo hello
#   .\scripts\dev-test.ps1 -Command 'exit 0'            # different test command
#   .\scripts\dev-test.ps1 -SkipBuild                   # just run + dump logs
#   .\scripts\dev-test.ps1 -Clean -Command 'echo hi'    # wipe old logs first
#   .\scripts\dev-test.ps1 -Tail 200 -ErrorOnly         # bigger daemon.log tail
#
# Designed to be edited freely as we learn more about the failure
# mode. Add new diagnostic dumps to the "Phase 4" block; everything
# above is plumbing.

[CmdletBinding()]
param(
  [string]$Command = 'echo hello',
  [switch]$SkipBuild,
  [switch]$Clean,
  [int]$Tail = 80,
  [switch]$ErrorOnly
)

$ErrorActionPreference = 'Continue'
$ScriptStart = Get-Date

# Resolve the repo root via the script's own location so the user can
# run this from any cwd (e.g. `pwsh scripts/dev-test.ps1`).
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$LogDir   = Join-Path $env:ProgramData 'dizgin\logs'

# Capture every byte the script prints into a fixed-name file under
# auto/ so the developer (and the assistant) can read a single
# location every iteration instead of chasing per-session paths.
# Older runs are preserved as last-test-run.<n>.log up to 3 deep.
$RunLogPath = Join-Path $RepoRoot 'auto\last-test-run.log'
$AutoDir = Split-Path $RunLogPath
if (-not (Test-Path $AutoDir)) {
  New-Item -ItemType Directory -Path $AutoDir -Force | Out-Null
}
if (Test-Path $RunLogPath) {
  for ($i = 2; $i -ge 1; $i--) {
    $src = Join-Path $AutoDir "last-test-run.$i.log"
    $dst = Join-Path $AutoDir ("last-test-run." + ($i + 1) + ".log")
    if (Test-Path $src) { Move-Item -LiteralPath $src -Destination $dst -Force }
  }
  Move-Item -LiteralPath $RunLogPath -Destination (Join-Path $AutoDir 'last-test-run.1.log') -Force
}
Start-Transcript -Path $RunLogPath -Force | Out-Null

function Write-Section([string]$Title) {
  Write-Host ''
  Write-Host ('=' * 60) -ForegroundColor Cyan
  Write-Host (" $Title") -ForegroundColor Cyan
  Write-Host ('=' * 60) -ForegroundColor Cyan
}

function Show-Log([string]$Path, [int]$TailN, [string]$Label) {
  if (-not (Test-Path $Path)) {
    Write-Host "[$Label] $Path not present" -ForegroundColor DarkYellow
    return
  }
  $size = (Get-Item $Path).Length
  Write-Host "[$Label] $Path ($size bytes, last $TailN lines)" -ForegroundColor DarkCyan
  Get-Content $Path -Tail $TailN
}

# Phase 1 -- optional clean of old broker stderr logs so the next dump
# only shows this iteration's output.
if ($Clean) {
  Write-Section 'Phase 1: clean old logs'
  if (Test-Path $LogDir) {
    Get-ChildItem (Join-Path $LogDir 'runhcs-*.stderr.log') -ErrorAction SilentlyContinue |
      Remove-Item -Force -ErrorAction SilentlyContinue
    # daemon.log is append-only across boots; truncate so the new boot
    # banner is the first thing we see.
    $daemonLog = Join-Path $LogDir 'daemon.log'
    if (Test-Path $daemonLog) {
      Set-Content -Path $daemonLog -Value '' -Encoding ascii -ErrorAction SilentlyContinue
    }
    Write-Host "  cleared $LogDir/runhcs-*.stderr.log + daemon.log"
  } else {
    Write-Host "  $LogDir does not exist yet"
  }
}

# Phase 2 -- build + install (skippable when iterating on the test
# command itself rather than the binaries).
if (-not $SkipBuild) {
  Write-Section 'Phase 2: make build install'
  Push-Location $RepoRoot
  try {
    & make build install
    if ($LASTEXITCODE -ne 0) {
      Write-Warning "make build install exited $LASTEXITCODE -- continuing anyway so logs are still dumped"
    }
  } finally {
    Pop-Location
  }
}

# Phase 3 -- run the test command. dizgin bootstraps dizgind automatically
# the first time, so we do not call dizgind start ourselves.
Write-Section "Phase 3: dizgin bash -c $Command"
& dizgin bash -c $Command
$copExit = $LASTEXITCODE
Write-Host ''
Write-Host "exit code: $copExit" -ForegroundColor $(if ($copExit -eq 0) { 'Green' } else { 'Red' })

# Phase 4 -- dump every log we have. daemon.log is the long-lived
# single source of truth; the per-session runhcs stderr files capture
# subprocess-level detail that the broker may not have time to mirror
# into daemon.log before runhcs exits.
Write-Section 'Phase 4: logs'

$daemonLog = Join-Path $LogDir 'daemon.log'
Show-Log $daemonLog $Tail 'daemon.log'

# Fixed-name logs from the most recent runhcs invocation. shim.log
# is the runhcs container shim's own diagnostic stream; vm.log is the
# UVM serial console + GCS bridge handshake. Together with daemon.log
# they cover every layer of the runhcs delegation path.
Write-Host ''
Show-Log (Join-Path $LogDir 'latest-shim.log') 200 'latest-shim.log'
Write-Host ''
Show-Log (Join-Path $LogDir 'latest-vm.log') 200 'latest-vm.log'
Write-Host ''
Show-Log (Join-Path $LogDir 'latest-runhcs.stderr.log') 200 'latest-runhcs.stderr.log'

Write-Host ''
$runhcsLogs = Get-ChildItem (Join-Path $LogDir 'runhcs-*.stderr.log') -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending
if (-not $runhcsLogs) {
  Write-Host '[runhcs] no per-session logs present' -ForegroundColor DarkYellow
} else {
  $latest = $runhcsLogs | Select-Object -First 1
  foreach ($f in $latest) {
    Write-Host ''
    Show-Log $f.FullName 100 "runhcs/$($f.Name)"
  }
}

# Optional: surface the latest dump-of-V2-doc files when present.
# Legacy from the custom HCS path; runhcs takes config.json, not the
# v2 schema dumps, so these files only appear if someone re-enables
# the old code paths.
Write-Host ''
$v2Docs = Get-ChildItem (Join-Path $LogDir 'v2-*.json') -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 3
if ($v2Docs) {
  Write-Host '[v2-*] legacy HCS schema dumps present (custom path active?):' -ForegroundColor DarkYellow
  $v2Docs | ForEach-Object { Write-Host "  $($_.FullName)" }
}

# Phase 5 -- show the OCI bundle config.json the broker generated for
# the most recent invocation. This is the actual contract between DIZGIN
# and runhcs; comparing it against a known-good bundle is the fastest
# way to spot a missing or malformed field.
Write-Section 'Phase 5: most recent OCI bundle config.json'
$layersDir = Join-Path $env:ProgramData 'dizgin\layers'
if (Test-Path $layersDir) {
  $latestBundle = Get-ChildItem $layersDir -Directory -Filter 'scratch-broker-*' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
  if ($latestBundle) {
    $cfg = Join-Path $latestBundle.FullName 'bundle\config.json'
    if (Test-Path $cfg) {
      Write-Host "[$($latestBundle.Name)/bundle/config.json]" -ForegroundColor DarkCyan
      Get-Content $cfg
    } else {
      Write-Host "  $cfg not present"
    }
  } else {
    Write-Host '  no scratch-broker-* directories found'
  }
}

# Phase 6 -- runhcs state directory contents. runhcs writes per-
# container state JSON here; if it exists but is stale, it tells us
# how far runhcs progressed before failing.
Write-Section 'Phase 6: runhcs state'
$stateDir = Join-Path $env:ProgramData 'dizgin\runhcs-state'
if (Test-Path $stateDir) {
  $sessions = Get-ChildItem $stateDir -Directory -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 3
  foreach ($s in $sessions) {
    Write-Host "  $($s.Name)/"
    Get-ChildItem $s.FullName -File -ErrorAction SilentlyContinue |
      ForEach-Object { Write-Host "    $($_.Name) ($($_.Length) bytes)" }
  }
  if (-not $sessions) { Write-Host '  (empty)' }
} else {
  Write-Host '  not present'
}

# Phase 7 -- hyper-V compute event log (recent 5 events). Surfaces any
# HCS-side rejection that did not make it back through runhcs's stderr.
Write-Section 'Phase 7: Hyper-V compute event log (last 5)'
try {
  Get-WinEvent -LogName 'Microsoft-Windows-Hyper-V-Compute-Operational' -MaxEvents 5 -ErrorAction Stop |
    ForEach-Object {
      $ts = $_.TimeCreated.ToString('HH:mm:ss')
      Write-Host "  [$ts] id=$($_.Id) $($_.Message)"
    }
} catch {
  Write-Host '  log not available (Hyper-V feature off or no events)'
}

$elapsed = (Get-Date) - $ScriptStart
Write-Section "Done in $([int]$elapsed.TotalSeconds)s -- dizgin exit $copExit"
Write-Host ''
Write-Host "Full transcript: $RunLogPath" -ForegroundColor DarkGreen
# Stop the transcript BEFORE Phase 8 so diagnose.ps1 can append to the
# same file via Add-Content. Start-Transcript holds an exclusive write
# lock; calling Add-Content while it is active yields IOException.
Stop-Transcript | Out-Null

# Phase 8 -- post-mortem dump on non-zero dizgin exit. Runs after
# Stop-Transcript so diagnose.ps1 can safely append its block to
# last-test-run.log without hitting the exclusive-write-lock.
if ($copExit -ne 0) {
  $diagnoseScript = Join-Path $RepoRoot 'scripts\diagnose.ps1'
  if (Test-Path $diagnoseScript) {
    & $diagnoseScript -OutPath $RunLogPath
  }
}
exit $copExit
