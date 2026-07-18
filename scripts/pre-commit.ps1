# DIZGIN pre-commit hook (Windows PowerShell).
# Mirrors scripts/pre-commit.sh; the wrapper script in scripts/git-hooks
# detects which one to run based on the host shell.

$ErrorActionPreference = "Stop"

# Run from repository root regardless of cwd.
$repoRoot = (& git rev-parse --show-toplevel) 2>$null
if (-not $repoRoot) { Write-Host "pre-commit: not a git repo"; exit 1 }
Set-Location $repoRoot

# 1. gofmt
$unformatted = (& gofmt -l .) -split "`n" | Where-Object { $_ }
if ($unformatted) {
    Write-Host "pre-commit: gofmt would change the following files:"
    $unformatted | ForEach-Object { Write-Host "  $_" }
    Write-Host "pre-commit: run 'gofmt -w -s .' (or 'make fmt') and re-stage."
    exit 1
}

# 2. go vet
& go vet ./...
if ($LASTEXITCODE -ne 0) { exit 1 }

# 3. golangci-lint (best-effort — only when installed)
$hasLint = (Get-Command golangci-lint -ErrorAction SilentlyContinue) -ne $null
if ($hasLint) {
    $stagedGo = (& git diff --cached --name-only --diff-filter=ACMRTUXB) -split "`n" |
        Where-Object { $_ -match '\.go$' }
    if ($stagedGo) {
        & golangci-lint run --new-from-rev=HEAD --timeout=2m
        if ($LASTEXITCODE -ne 0) { exit 1 }
    }
}

Write-Host "pre-commit: ok"
