#!/usr/bin/env bash
# DIZGIN pre-push hook (Unix shell).
# Wired via `make hooks-install`, delegated from scripts/git-hooks/pre-push.
# Runs the full validation gate — the same set `make release` relies on to
# guarantee it runs exactly once per release (via this hook when there is
# something to push, or inline via a direct call to this script when there
# is not). Every `git push` on this repo pays this cost once hooks are
# installed; that is intentional (see CONTRIBUTING.md).
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

echo "pre-push: [1/6] gofmt"
unformatted=$(gofmt -l .)
if [[ -n "${unformatted}" ]]; then
  echo "pre-push: gofmt would change the following files:"
  echo "${unformatted}" | sed 's/^/  /'
  echo "pre-push: run 'make fmt' and commit the result."
  exit 1
fi

echo "pre-push: [2/6] lint (go vet + golangci-lint)"
if ! command -v golangci-lint >/dev/null 2>&1; then
  echo "pre-push: golangci-lint not found on PATH. Run 'make tool-install'." >&2
  exit 1
fi
make lint

echo "pre-push: [3/6] build (typecheck)"
make build

echo "pre-push: [4/6] test"
make test

echo "pre-push: [5/6] dependency audit (govulncheck)"
if ! command -v govulncheck >/dev/null 2>&1; then
  echo "pre-push: govulncheck not found on PATH. Run 'make tool-install'." >&2
  exit 1
fi
make vuln

echo "pre-push: [6/6] e2e"
make e2e

echo "pre-push: full gate passed"
