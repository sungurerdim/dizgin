# DIZGIN post-mortem diagnose dump -- Windows
#
# Manual entry point (`make diagnose`) and auto-call from
# scripts/dev-test.ps1 on non-zero dizgin exit. Captures the full
# runhcs / Hyper-V / vmcompute snapshot and appends it to
# auto/last-test-run.log under a `=== POST-MORTEM ===` banner so
# the next iteration only has to read one fixed file.
#
# Usage:
#   .\scripts\diagnose.ps1                          # write to auto\last-test-run.log
#   .\scripts\diagnose.ps1 -OutPath custom.log      # alternate output
#   .\scripts\diagnose.ps1 -Append:$false           # overwrite instead of append
#
# Designed to be run in any shell -- pwsh or windows-powershell.
# Every command is best-effort: a missing tool, locked event log, or
# non-existent state directory just prints an annotated note and
# the script keeps going. Goal: never fail the whole snapshot
# because one feature is unavailable.

[CmdletBinding()]
param(
  [string]$OutPath,
  [bool]$Append = $true
)

$ErrorActionPreference = 'Continue'

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
if (-not $OutPath) {
  $OutPath = Join-Path $RepoRoot 'auto\last-test-run.log'
}
$AutoDir = Split-Path $OutPath
if (-not (Test-Path $AutoDir)) {
  New-Item -ItemType Directory -Path $AutoDir -Force | Out-Null
}

$LogDir   = Join-Path $env:ProgramData 'dizgin\logs'
$BinDir   = Join-Path $env:ProgramData 'dizgin\bin'
$Runhcs   = Join-Path $BinDir 'runhcs.exe'
$RunhcsRoot = Join-Path $env:ProgramData 'dizgin\runhcs-root'

function Out-Line([string]$s) {
  if ($Append) {
    Add-Content -LiteralPath $OutPath -Value $s -Encoding utf8
  } else {
    Set-Content -LiteralPath $OutPath -Value $s -Encoding utf8
    $script:Append = $true   # subsequent calls append
  }
}

function Out-Section([string]$Title) {
  Out-Line ''
  Out-Line ('-' * 60)
  Out-Line " $Title"
  Out-Line ('-' * 60)
}

Out-Line ''
Out-Line '============================================================'
Out-Line " === POST-MORTEM === $(Get-Date -Format o)"
Out-Line '============================================================'

# 1. Binary metadata. Confirms which build is on disk vs. running.
Out-Section 'binaries (%ProgramData%\dizgin\bin)'
foreach ($name in 'dizgin.exe', 'dizgind.exe', 'runhcs.exe') {
  $p = Join-Path $BinDir $name
  if (Test-Path $p) {
    $i = Get-Item $p
    Out-Line ("  {0,-14}  {1,12} bytes  {2:o}" -f $name, $i.Length, $i.LastWriteTimeUtc)
  } else {
    Out-Line "  $name  MISSING"
  }
}

# 2. runhcs container registry. Stale entries here usually point at
#    a container that crashed after vmshim split off but before delete
#    completed -- the surviving entry blocks the next start with
#    "container ID already exists".
Out-Section 'runhcs --root <root> list'
if (Test-Path $Runhcs) {
  if (Test-Path $RunhcsRoot) {
    & $Runhcs --root $RunhcsRoot list 2>&1 | ForEach-Object { Out-Line "  $_" }
  } else {
    Out-Line "  runhcs root not present at $RunhcsRoot"
  }
} else {
  Out-Line "  $Runhcs missing"
}

# 3. State directory. runhcs writes one subdir per live container,
#    deepest evidence of where the runtime got to before failing.
Out-Section 'runhcs state directory'
$stateDir = Join-Path $env:ProgramData 'dizgin\runhcs-state'
if (Test-Path $stateDir) {
  $sessions = Get-ChildItem $stateDir -Directory -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 5
  if (-not $sessions) { Out-Line '  (empty)' }
  foreach ($s in $sessions) {
    Out-Line "  $($s.Name)/  ($($s.LastWriteTimeUtc.ToString('o')))"
    Get-ChildItem $s.FullName -File -ErrorAction SilentlyContinue |
      ForEach-Object { Out-Line "    $($_.Name) ($($_.Length) bytes)" }
  }
} else {
  Out-Line '  not present'
}

# 4. Hyper-V Compute event log -- last 10. Captures vmcompute-side
#    rejections that runhcs does not surface in stderr.
Out-Section 'Microsoft-Windows-Hyper-V-Compute-Operational (last 10)'
try {
  Get-WinEvent -LogName 'Microsoft-Windows-Hyper-V-Compute-Operational' -MaxEvents 10 -ErrorAction Stop |
    ForEach-Object {
      $ts = $_.TimeCreated.ToString('HH:mm:ss')
      $msg = ($_.Message -split [Environment]::NewLine | Select-Object -First 1)
      Out-Line "  [$ts] id=$($_.Id) $msg"
    }
} catch {
  Out-Line '  log not available (Hyper-V feature off or no events)'
}

# 5. Hyper-V Worker / VMMS event logs -- recent 10 each. Surfaces
#    Worker-process and VM-management-side errors that vmcompute
#    leaves to the worker.
Out-Section 'Microsoft-Windows-Hyper-V-Worker-Admin (last 5)'
try {
  Get-WinEvent -LogName 'Microsoft-Windows-Hyper-V-Worker-Admin' -MaxEvents 5 -ErrorAction Stop |
    ForEach-Object {
      $ts = $_.TimeCreated.ToString('HH:mm:ss')
      $msg = ($_.Message -split [Environment]::NewLine | Select-Object -First 1)
      Out-Line "  [$ts] id=$($_.Id) $msg"
    }
} catch {
  Out-Line '  log not available'
}
Out-Section 'Microsoft-Windows-Hyper-V-VMMS-Admin (last 5)'
try {
  Get-WinEvent -LogName 'Microsoft-Windows-Hyper-V-VMMS-Admin' -MaxEvents 5 -ErrorAction Stop |
    ForEach-Object {
      $ts = $_.TimeCreated.ToString('HH:mm:ss')
      $msg = ($_.Message -split [Environment]::NewLine | Select-Object -First 1)
      Out-Line "  [$ts] id=$($_.Id) $msg"
    }
} catch {
  Out-Line '  log not available'
}

# 6. Process tree. Filtered to the DIZGIN chain so leaked subprocesses
#    are obvious -- runhcs/vmshim hangs are a recurring failure mode.
Out-Section 'process tree (dizgin / dizgind / runhcs / vmshim / vmwp)'
try {
  Get-CimInstance Win32_Process -ErrorAction Stop |
    Where-Object {
      $_.Name -match '(?i)^(dizgin|dizgind|runhcs|vmshim|vmwp|vmcompute)\.exe$'
    } |
    Sort-Object ParentProcessId, ProcessId |
    ForEach-Object {
      Out-Line ("  pid={0,-6} ppid={1,-6} {2,-18} {3}" -f $_.ProcessId, $_.ParentProcessId, $_.Name, $_.CommandLine)
    }
} catch {
  Out-Line "  Get-CimInstance failed: $($_.Exception.Message)"
}

# 7. vmcompute service registry snapshot. Confirms the service is
#    installed at the correct image path and not in a half-disabled
#    state -- a registry key edit by some other tool would manifest
#    as silent vmcompute non-start.
Out-Section 'HKLM:SYSTEM\CurrentControlSet\Services\vmcompute'
try {
  $svc = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\vmcompute' -ErrorAction Stop
  foreach ($name in 'ImagePath', 'Start', 'ObjectName', 'DisplayName') {
    Out-Line ("  {0}: {1}" -f $name, $svc.$name)
  }
} catch {
  Out-Line "  registry read failed: $($_.Exception.Message)"
}

# 8. Latest log files (sizes + last write). Quick sanity check that
#    daemon.log and friends actually exist and are recent. The
#    contents themselves live in the Phase 4 dump dev-test.ps1
#    already prints; no point duplicating them here.
Out-Section 'log files (sizes only -- contents in Phase 4)'
if (Test-Path $LogDir) {
  Get-ChildItem $LogDir -File -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 12 |
    ForEach-Object {
      Out-Line ("  {0,12} bytes  {1:o}  {2}" -f $_.Length, $_.LastWriteTimeUtc, $_.Name)
    }
} else {
  Out-Line "  $LogDir not present"
}

Out-Line ''
Out-Line "=== /POST-MORTEM ==="
Out-Line ''

Write-Host "diagnose: appended post-mortem block to $OutPath" -ForegroundColor DarkGreen
