# DIZGIN pre-push hook (Windows PowerShell).
# Mirrors scripts/pre-push.sh; the wrapper script in scripts/git-hooks
# detects which one to run based on the host shell. See pre-push.sh for
# why every push pays this cost once hooks are installed.

$ErrorActionPreference = "Stop"

$repoRoot = (& git rev-parse --show-toplevel) 2>$null
if (-not $repoRoot) { Write-Host "pre-push: not a git repo"; exit 1 }
Set-Location $repoRoot

Write-Host "pre-push: [1/6] gofmt"
$unformatted = (& gofmt -l .) -split "`n" | Where-Object { $_ }
if ($unformatted) {
    Write-Host "pre-push: gofmt would change the following files:"
    $unformatted | ForEach-Object { Write-Host "  $_" }
    Write-Host "pre-push: run 'make fmt' and commit the result."
    exit 1
}

Write-Host "pre-push: [2/6] lint (go vet + golangci-lint)"
if (-not (Get-Command golangci-lint -ErrorAction SilentlyContinue)) {
    Write-Host "pre-push: golangci-lint not found on PATH. Run 'make tool-install'."
    exit 1
}
& make lint
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "pre-push: [3/6] build (typecheck)"
& make build
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "pre-push: [4/6] test"
& make test
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "pre-push: [5/6] dependency audit (govulncheck)"
if (-not (Get-Command govulncheck -ErrorAction SilentlyContinue)) {
    Write-Host "pre-push: govulncheck not found on PATH. Run 'make tool-install'."
    exit 1
}
& make vuln
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "pre-push: [6/6] e2e"
& make e2e
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "pre-push: full gate passed"
