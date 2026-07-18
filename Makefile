.PHONY: build test lint fmt tidy clean install schema cover check e2e vuln smoke diagnose hooks-install hooks-uninstall release-snapshot tool-install rename

NAME       := dizgin
DAEMON     := $(NAME)d
GOFLAGS    := -trimpath -buildvcs=true
BINDIR     := bin

# Build metadata. We intentionally avoid shell-specific constructs in these
# $(shell ...) calls so the Makefile works whether make's shell is bash,
# sh.exe, or cmd.exe — the GnuWin32 port we install on Windows will happily
# pick any of the three depending on PATH, and a construct like `2>/dev/null`
# or `$$null` breaks silently in the non-matching shell.
#
# Dates come from PowerShell on Windows (`Get-Date -Format` is cmd/bash-neutral
# because the format argument is just quoted text) and from GNU `date` on
# Unix. Git commands work from any shell; when invoked outside a repo their
# stderr prints a one-off warning to the console but $(shell) captures only
# stdout so the Makefile variables still end up empty, and VERSION safely
# falls back to dev-<timestamp>.
ifeq ($(OS),Windows_NT)
  EXE        := .exe
  BUILD_TS   := $(shell powershell -NoProfile -Command "Get-Date -Format yyyyMMddTHHmmssZ")
else
  EXE        :=
  BUILD_TS   := $(shell date -u +%Y%m%dT%H%M%SZ)
endif

# Reproducible builds (Phase 1 plan, item D2): use the commit's author
# timestamp as the embedded build date, not "now". Two builds of the
# same commit on different machines produce identical bytes — modulo
# Go's CGO toolchain version, which is pinned via go.mod's `go 1.25`
# directive and the matching GHA setup-go pin.
#
# Falls back to BUILD_TS when not in a git repo (e.g. tarball release
# extracted into a fresh dir) so `make build` still works for
# downstream packagers without git history.
GIT_COMMIT_DATE := $(shell git log -1 --format=%cI 2>/dev/null)
BUILD_TIME      := $(if $(GIT_COMMIT_DATE),$(GIT_COMMIT_DATE),$(BUILD_TS))

# `git tag --points-at HEAD` is the cross-shell silent equivalent of
# `git describe --tags --exact-match` — when no tag points at the
# current commit it prints an empty stdout instead of a stderr "fatal:
# No names found" message that leaked through every `make` invocation.
GIT_TAG    := $(shell git tag --points-at HEAD)
GIT_COMMIT := $(shell git rev-parse --short HEAD)

VERSION    := $(if $(GIT_TAG),$(GIT_TAG),dev-$(BUILD_TS))
GIT_COMMIT := $(if $(GIT_COMMIT),$(GIT_COMMIT),none)
LDFLAGS    := -s -w -X main.version=$(VERSION) -X main.commit=$(GIT_COMMIT) -X main.date=$(BUILD_TIME)

build:
# Wipe bin/ inline (NOT as a make prerequisite) so the wipe always
# happens BEFORE the go build invocations below. Declaring `build:
# clean` would let GNU make schedule the prerequisites in any order
# under -j or even in some serial setups -- empirically observed to
# clean bin/ AFTER building, leaving install with no binary to copy.
ifeq ($(OS),Windows_NT)
	powershell -NoProfile -Command "if (Test-Path '$(BINDIR)') { Remove-Item -Recurse -Force '$(BINDIR)' }"
else
	rm -rf $(BINDIR)
endif
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINDIR)/$(NAME)$(EXE) ./cmd/$(NAME)
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINDIR)/$(DAEMON)$(EXE) ./cmd/$(DAEMON)

install: build
# build now wipes bin/ inline before recompiling, so the install body
# always sees freshly built binaries. The full install sequence is:
#  1. build (rm bin/, then dizgin + dizgind)
#  2. dizgind stop (graceful daemon IPC shutdown)
#  3. install.ps1 (kills holdout processes + wipes %ProgramData%\dizgin
#     state through a single elevated subprocess, then copies the
#     fresh binaries into place)
#  4. dizgind start (autoSetup + daemon start under one UAC prompt)
# Graceful IPC shutdown first. dizgind stop sends a Shutdown message through
# the daemon's named pipe, so the running daemon (which may be elevated) exits
# itself — that matters because install.ps1's Stop-Process -Force cannot reach
# an elevated daemon from a non-elevated shell, leaving the old binary running
# even after install copies a new one. The `-` prefix ignores errors when the
# daemon is not running (first-time install, already stopped, etc.).
	-$(DAEMON) stop
# Single-line powershell invocation — GnuWin32 make under cmd.exe would pass
# backslash line continuations through literally and break the command line.
	powershell -NoProfile -ExecutionPolicy Bypass -File scripts/install.ps1 -LocalBinary $(BINDIR)/$(NAME)$(EXE)
# Single elevated invocation: `dizgind start` runs autoSetup() at the top of
# its boot path, so the base image / Hyper-V feature / scratch template /
# NAT network are all verified inside the same UAC-elevated process that
# brings the daemon up. Splitting setup and start into separate commands
# would force two UAC prompts back-to-back. The `-` prefix keeps make
# install green on non-Windows and on first-time installs where dizgind
# is not yet on PATH when make invokes it.
	-$(DAEMON) start

test:
	go test -race -count=1 -parallel 4 ./...

lint:
	go vet ./...
	golangci-lint run

fmt:
	gofmt -w -s .

tidy:
	go mod tidy

clean:
ifeq ($(OS),Windows_NT)
	powershell -NoProfile -Command "if (Test-Path '$(BINDIR)') { Remove-Item -Recurse -Force '$(BINDIR)' }"
else
	rm -rf $(BINDIR)
endif

schema:
	go run -tags schemagen ./cmd/schemagen > schema/$(NAME).schema.json

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

check: lint test cover

e2e: build
# The e2e tests resolve dizgin/dizgind via tests/e2e/testdata/ — copy the
# freshly built binaries there so the suite finds them. Without this
# pre-step every test silently SKIPs ("dizgin.exe not found"), which makes
# the suite look green when in fact nothing ran.
ifeq ($(OS),Windows_NT)
	powershell -NoProfile -Command "New-Item -ItemType Directory -Force -Path tests/e2e/testdata | Out-Null; Copy-Item '$(BINDIR)/$(NAME)$(EXE)' 'tests/e2e/testdata/$(NAME)$(EXE)' -Force; Copy-Item '$(BINDIR)/$(DAEMON)$(EXE)' 'tests/e2e/testdata/$(DAEMON)$(EXE)' -Force"
else
	mkdir -p tests/e2e/testdata
	cp $(BINDIR)/$(NAME)$(EXE) tests/e2e/testdata/$(NAME)$(EXE)
	cp $(BINDIR)/$(DAEMON)$(EXE) tests/e2e/testdata/$(DAEMON)$(EXE)
endif
	go test -tags=integration -timeout 300s ./tests/e2e/...
ifeq ($(OS),Windows_NT)
	-powershell -NoProfile -Command "Remove-Item -Force 'tests/e2e/testdata/$(NAME)$(EXE)','tests/e2e/testdata/$(DAEMON)$(EXE)' -ErrorAction SilentlyContinue"
else
	-rm -f tests/e2e/testdata/$(NAME)$(EXE) tests/e2e/testdata/$(DAEMON)$(EXE)
endif

vuln:
	govulncheck ./...

# End-to-end smoke for the restricted Windows backend. Builds + installs,
# runs a fixed scenario list (R2 happy path, R1 fail-closed against host
# secrets, profile reaping), and writes a single transcript to
# auto/last-test-run.log. Use SKIP_BUILD=1 to iterate on the test cases
# without recompiling. The legacy HCS dev-test.ps1 still exists for
# DIZGIN_FORCE_CONTAINER=1 inner-loop debugging — it is no longer wired to
# `make smoke`.
smoke:
	powershell -NoProfile -ExecutionPolicy Bypass -File scripts/smoke.ps1 $(if $(SKIP_BUILD),-SkipBuild,)

# Manual post-mortem snapshot. Appends a `=== POST-MORTEM ===` block
# to auto/last-test-run.log with runhcs / Hyper-V / vmcompute state.
# dev-test.ps1 calls the same script automatically on non-zero dizgin
# exit; this target is for ad-hoc inspection without re-running dizgin.
diagnose:
	powershell -NoProfile -ExecutionPolicy Bypass -File scripts/diagnose.ps1

# Wire git's pre-commit hook into scripts/git-hooks. Idempotent —
# running this twice has no extra effect. Uninstall with hooks-uninstall.
hooks-install:
	git config core.hooksPath scripts/git-hooks
	@echo "hooks-install: core.hooksPath -> scripts/git-hooks"

hooks-uninstall:
	git config --unset core.hooksPath || true
	@echo "hooks-uninstall: core.hooksPath cleared"

# GoReleaser dry-run. Builds every target tuple in .goreleaser.yaml,
# verifies archive layouts and checksum files, and writes the result
# under dist/. Nothing is uploaded — this is purely for local
# verification before tagging.
release-snapshot:
	goreleaser release --snapshot --clean

# Install all quality-gate tools required to run `make lint`, `make vuln`,
# and `make release-snapshot` locally. Idempotent — safe to run repeatedly.
tool-install:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
	go install golang.org/x/vuln/cmd/govulncheck@v1.6.0
	go install github.com/goreleaser/goreleaser/v2@v2.17.0

# One-command product rename (module path, cmd/ dirs, packaging, docs).
# internal/brand/brand.go is the runtime name SSOT; this covers the rest.
rename:
	@test -n "$(NEW)" || { echo "usage: make rename NEW=<newname>"; exit 1; }
	bash scripts/rename.sh $(NEW)
