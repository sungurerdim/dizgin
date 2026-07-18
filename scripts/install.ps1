# DIZGIN installer -- Windows (PowerShell)
# Installs dizgin and dizgind to the first writable directory already in PATH.
# Never modifies PATH.
#
# Usage (release):
#   irm https://raw.githubusercontent.com/sungurerdim/dizgin/main/scripts/install.ps1 | iex
#
# Usage (local test -- skips download/verify):
#   .\scripts\install.ps1 -LocalBinary .\bin\dizgin.exe
[CmdletBinding()]
param(
  [string]$LocalBinary   # path to a locally built dizgin.exe; skips download + checksum
)
$ErrorActionPreference = 'Stop'

$Repo    = 'sungurerdim/dizgin'
$ApiUrl  = "https://api.github.com/repos/$Repo/releases/latest"

# -- helpers ------------------------------------------------------------------

function Get-Platform {
  $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' }
          elseif ([System.Environment]::Is64BitOperatingSystem) { 'amd64' }
          else { throw "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
  return $arch
}

# Returns the directory where DIZGIN is already installed, or $null.
function Get-ExistingInstallDir {
  $found = Get-Command 'dizgin' -ErrorAction SilentlyContinue
  if ($found) { return Split-Path $found.Source }
  return $null
}

# Tests whether a directory is writable by creating and deleting a temp file.
function Test-Writable([string]$Dir) {
  if (-not (Test-Path $Dir -PathType Container)) { return $false }
  try {
    $tmp = Join-Path $Dir (".dizgin_write_test_" + [System.IO.Path]::GetRandomFileName())
    [System.IO.File]::WriteAllText($tmp, '')
    Remove-Item $tmp -Force
    return $true
  } catch {
    return $false
  }
}

# Finds the best writable directory already in PATH. Never adds to PATH.
function Find-InstallDir {
  # Prefer the directory where DIZGIN is already installed.
  $existing = Get-ExistingInstallDir
  if ($existing -and (Test-Writable $existing)) { return $existing }

  # Search PATH entries (User PATH before System PATH).
  $userPath   = [System.Environment]::GetEnvironmentVariable('PATH', 'User')   -split ';'
  $systemPath = [System.Environment]::GetEnvironmentVariable('PATH', 'Machine') -split ';'

  foreach ($dir in ($userPath + $systemPath)) {
    $dir = $dir.Trim()
    if ($dir -and (Test-Writable $dir)) { return $dir }
  }
  return $null
}

function Get-Sha256([string]$FilePath) {
  return (Get-FileHash $FilePath -Algorithm SHA256).Hash.ToLower()
}

function Confirm-Checksum([string]$FilePath, [string]$ChecksumsPath, [string]$AssetName) {
  $lines = Get-Content $ChecksumsPath
  $entry = $lines | Where-Object { $_ -match "\s$([regex]::Escape($AssetName))$" }
  if (-not $entry) { throw "Checksum entry not found for $AssetName" }
  $expected = ($entry -split '\s+')[0].Trim()
  $actual   = Get-Sha256 $FilePath
  if ($actual -ne $expected) {
    throw "Checksum mismatch for ${AssetName}:`n  got  $actual`n  want $expected"
  }
}

function Install-Binary([string]$Src, [string]$Name, [string]$Dir) {
  Copy-Item $Src (Join-Path $Dir $Name) -Force
  Write-Host "  $Name -> $Dir\$Name"
}

# Terminates running dizgin and dizgind processes so their file handles are
# released before the installer overwrites the binaries.
# dizgind is stopped first -- it holds HCS container handles; stopping it
# signals any active dizgin sessions through the broker before dizgin itself exits.
function Test-IsElevated {
  $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Terminates running dizgin and dizgind processes so their file handles
# are released before the installer overwrites the binaries. dizgind is
# stopped first -- it owns the AppContainer profile cleanup loop and
# the IPC named pipe; stopping it cleanly lets active dizgin sessions
# revoke their transient stamps via Box.Cleanup before exit.
function Stop-DIZGINProcesses {
  $stopped = $false
  $needsElevation = $false
  foreach ($name in @('dizgind', 'dizgin')) {
    $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
    if (-not $procs) { continue }
    $count = @($procs).Count
    Write-Host "  Stopping $name.exe ($count running instance$(if ($count -ne 1) { 's' }))..."
    foreach ($p in $procs) {
      try {
        Stop-Process -Id $p.Id -Force -ErrorAction Stop
        $stopped = $true
      } catch {
        # Access denied = process owned by an elevated session we
        # cannot reach from this token.
        $needsElevation = $true
      }
    }
  }
  if ($needsElevation -and -not (Test-IsElevated)) {
    Write-Host '  Stopping elevated daemon (UAC prompt)...'
    $cleanScript = @'
foreach ($name in @('dizgind','dizgin')) {
  $p = Get-Process -Name $name -ErrorAction SilentlyContinue
  if ($p) { $p | Stop-Process -Force -ErrorAction SilentlyContinue }
}
'@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cleanScript))
    Start-Process -FilePath 'powershell.exe' -ArgumentList @(
      '-NoProfile', '-ExecutionPolicy', 'Bypass',
      '-WindowStyle', 'Hidden',
      '-EncodedCommand', $encoded
    ) -Verb RunAs -Wait
    $stopped = $true
  }
  if ($stopped) {
    # Brief pause so Windows releases file handles before we overwrite the binaries.
    Start-Sleep -Milliseconds 800
  }
}

# -- main ---------------------------------------------------------------------

$arch = Get-Platform

# Find install directory.
$installDir = Find-InstallDir
if (-not $installDir) {
  Write-Error @"
No writable directory found in PATH.

Directories checked (none are writable):
$( ($env:PATH -split ';' | Where-Object { $_ } | ForEach-Object { "  $_" }) -join "`n" )

Add a writable directory to PATH first, then re-run this installer.
"@
  exit 1
}

# -- local test mode -----------------------------------------------------------
if ($LocalBinary) {
  $LocalBinary = Resolve-Path $LocalBinary
  $localDir    = Split-Path $LocalBinary
  Write-Host "Local binary: $LocalBinary"
  Write-Host 'Stopping existing processes...'
  Stop-DIZGINProcesses
  Write-Host 'Installing...'
  Install-Binary $LocalBinary 'dizgin.exe' $installDir

  # Install dizgind if present alongside dizgin.
  $localDaemon = Join-Path $localDir 'dizgind.exe'
  if (Test-Path $localDaemon) {
    Install-Binary $localDaemon 'dizgind.exe' $installDir
  }

  # Install profiles directory if present alongside dizgin.
  $localProfiles = Join-Path $localDir 'profiles'
  if (Test-Path $localProfiles -PathType Container) {
    $destProfiles = Join-Path $installDir 'profiles'
    if (Test-Path $destProfiles) {
      Remove-Item $destProfiles -Recurse -Force
    }
    Copy-Item $localProfiles $destProfiles -Recurse -Force
    Write-Host "  profiles/ -> $installDir\profiles\"
  }

  Write-Host ""
  Write-Host "DIZGIN (local build) installed -> $installDir"
  exit 0
}

# -- release mode -------------------------------------------------------------
Write-Host 'Fetching latest release...'
$release      = Invoke-RestMethod $ApiUrl
$version      = $release.tag_name                       # e.g. "v0.1.0"
$versionStrip = $version.TrimStart('v')                 # e.g. "0.1.0"
$checksumUrl  = "https://github.com/$Repo/releases/download/$version/checksums.txt"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmp | Out-Null

try {
  Write-Host 'Downloading checksums...'
  Invoke-WebRequest $checksumUrl -OutFile (Join-Path $tmp 'checksums.txt')

  Write-Host 'Stopping existing processes...'
  Stop-DIZGINProcesses
  Write-Host 'Installing...'
  foreach ($bin in @('dizgin', 'dizgind')) {
    $assetName = "cop_${versionStrip}_windows_${arch}.zip"
    # dizgind uses its own archive name
    if ($bin -eq 'dizgind') {
      $assetName = "station_${versionStrip}_windows_${arch}.zip"
    }
    $assetUrl = "https://github.com/$Repo/releases/download/$version/$assetName"

    Write-Host "  Downloading $assetName..."
    Invoke-WebRequest $assetUrl -OutFile (Join-Path $tmp $assetName)

    Confirm-Checksum (Join-Path $tmp $assetName) (Join-Path $tmp 'checksums.txt') $assetName

    Expand-Archive (Join-Path $tmp $assetName) -DestinationPath (Join-Path $tmp $bin) -Force
    Copy-Item (Join-Path $tmp $bin "$bin.exe") (Join-Path $installDir "$bin.exe") -Force
    Write-Host "  $bin.exe -> $installDir\$bin.exe"
  }

  Write-Host ""
  Write-Host "DIZGIN $version installed -> $installDir"
} finally {
  Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
