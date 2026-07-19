#!/usr/bin/env bash
# DIZGIN pre-commit hook (Unix shell).
# Wired via `make hooks-install` which runs:
#   git config core.hooksPath scripts/git-hooks
# That points git at scripts/git-hooks/pre-commit which delegates here.
set -euo pipefail

# Run from repository root regardless of where the user invoked git.
cd "$(git rev-parse --show-toplevel)"

# 1. gofmt — fail when any file under the working tree is not formatted.
unformatted=$(gofmt -l .)
if [[ -n "${unformatted}" ]]; then
  echo "pre-commit: gofmt would change the following files:"
  echo "${unformatted}" | sed 's/^/  /'
  echo "pre-commit: run 'gofmt -w -s .' (or 'make fmt') and re-stage."
  exit 1
fi

# 2. go vet — cheap, surfaces obvious type / format mistakes.
go vet ./...

# 3. golangci-lint — only when available. We do not require contributors
#    to install it locally; CI is the binding check. When it is on PATH
#    we run the changed-files-only mode so the hook stays sub-second.
if command -v golangci-lint >/dev/null 2>&1; then
  if git diff --cached --name-only --diff-filter=ACMRTUXB | grep -qE '\.go$'; then
    golangci-lint run --new-from-rev=HEAD --timeout=2m
  fi
fi

echo "pre-commit: ok"
