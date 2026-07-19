# Contributing to DIZGIN

## Reporting Security Issues

Security vulnerabilities **must not** be filed as public issues or PRs.
See [`SECURITY.md`](SECURITY.md) for the disclosure procedure (private
GitHub Security Advisory or `sungurerdim@gmail.com`).

## Conventional Commits

Commit messages follow the [Conventional Commits](https://www.conventionalcommits.org/) spec.
The litmus test for the type prefix:

| Type        | When to use                                                           |
|-------------|-----------------------------------------------------------------------|
| `feat:`     | end users can do something they could not before (minor version bump) |
| `fix:`      | something was broken for end users and now works (patch version bump) |
| `refactor:` | internal structure change, no user-visible effect                     |
| `chore:`    | build / tooling / housekeeping                                        |
| `test:`     | tests only                                                            |
| `docs:`     | documentation only                                                    |
| `ci:`       | CI configuration only                                                 |

If you are unsure, pick the non-bumping type. `ci: fix config` does
not bump the version; `fix(ci): fix config` would.

Example:

```
fix(dizgin): graceful daemon degradation on warm start

Reduce ensureDaemonRunning warm-start wait from 60 s to 15 s so
misconfigurations fail fast instead of holding the suite hostage.
```

## Prerequisites

- Go 1.25+
- `golangci-lint` v2.11+ (`go install github.com/golangci/golangci-lint/cmd/golangci-lint@v2.11.3`)
- Windows (recommended for full restricted-backend testing), or macOS/Linux for seatbelt/bubblewrap backends

## Development Workflow

```bash
# Build both binaries
make build
# or manually:
go build -trimpath -o bin/dizgin.exe ./cmd/dizgin
go build -trimpath -o bin/dizgind.exe ./cmd/dizgind

# Run tests
make test
# or: go test -race -count=1 ./...

# Lint (go vet + golangci-lint)
make lint

# Format code
make fmt

# Tidy module dependencies
make tidy
```

## Project Structure

```
cmd/dizgin/          — Sandbox wrapper binary
cmd/dizgind/         — Orchestration daemon binary
internal/sandbox/     — Backend implementations (restricted, seatbelt, bubblewrap)
internal/daemon/      — IPC server/client, instance registry
internal/config/      — Config loader, tool mount maps
internal/credential/  — SSH, API key, GitHub token discovery
internal/platform/    — OS detection, suspend/resume
tests/e2e/            — End-to-end integration tests
```

## Adding a New Sandbox Backend

1. Create `internal/sandbox/<name>/backend.go` implementing `sandbox.Backend` and `sandbox.Box`
2. Add a build-tagged blank import in `cmd/dizgin/backends_<os>.go` (or `backends_other.go`)
3. Register via `sandbox.Register()` in an `init()` function
4. Add E2E tests in `tests/e2e/`

## Adding a new profile

Tool profiles live in `profiles/*.yaml` and are the single source of
truth for which mounts, env vars, and runtime each AI tool needs.
`internal/config/tools.go::builtinTools` is intentionally empty — do
NOT add Go-level entries there.

1. **Create the YAML.** Pick the canonical tool name as the filename
   (lowercase, no `.exe` suffix). Minimum required fields:

    ```yaml
    name: mytool
    version: 1
    updated: "2026-05-06"
    description: "What this tool does in one line"
    binary: mytool          # the host-side executable name
    runtime: nodejs         # one of: nodejs / bun / python / go / rust / dotnet / standalone
    config_dirs:
      - "~/.mytool"
      - "%APPDATA%/mytool"
    env_keys:
      - MYTOOL_API_KEY
    ```

   Optional fields: `tool_deps`, `lib_deps`, `mcp_dirs`, `runtime_dirs`,
   `default_args`, `env`, `passthrough`, `network.hosts`. Schema is
   strict — unknown keys cause a load-time failure (see `dizgin doctor`).

2. **Verify the loader accepts it.** From the repo root:

    ```bash
    go test -run TestParseProfile_AllBundledProfilesParseCleanly ./internal/config
    dizgin doctor
    ```

   The first test re-runs the strict-mode loader against every
   bundled profile; `dizgin doctor` emits a clean "profiles load — N
   loaded" line when your file parses.

3. **Add a regression test.** A tiny entry in
   `internal/config/profiles_test.go` that asserts the tool resolves
   under `LookupTool` (e.g.
   `TestEffectiveToolDeps_<MyTool>_IncludesGitDefault`) catches
   accidental field renames in future refactors.

4. **Update `docs/QUICKSTART.md`** if the new tool is one a typical
   user will ask dizgin to wrap (claude, aider, etc.). Skip this for
   niche tools.

5. **Submit a PR with `feat(profiles): add <toolname>` as the
   commit subject.** Profile additions count as user-facing capability
   → `feat:` is correct.

The `defaultTools` Go map referenced in earlier docs no longer
exists — that pattern was retired in 2026-Q1 in favour of the YAML
SSOT. If a downstream tool tries to import `config.defaultTools`,
update it to call `config.LookupTool(name)` instead.

## Testing Strategy

DIZGIN focuses on **critical-path tests** rather than coverage targets:

- **Sandbox backends** — Container creation, filesystem isolation, process lifecycle
- **Daemon IPC** — Message codec, register/heartbeat/deregister, named pipe/unix socket transport
- **Config loading** — YAML parsing, validation, tool profile resolution, defaults
- **Credential discovery** — API key scanning, SSH agent detection, GitHub token resolution

Tests live in `_test.go` files in the same package (white-box testing). Run with:

```bash
make test        # go test -race -count=1 -parallel 4 ./...
make e2e         # integration tests (requires built binaries)
```

### Pre-commit hooks

The repo ships pre-commit hooks under `scripts/git-hooks/` that run
`go vet`, `golangci-lint`, and a basic profile-schema sanity pass on
every commit. Wire them into your local repo with:

```bash
make hooks-install   # sets core.hooksPath to scripts/git-hooks
```

After install, every `git commit` blocks if vet / lint / schema
sanity fails. Bypass with `git commit --no-verify` only when you
have a specific reason — opening a draft PR for review is preferred
over committing known-broken code locally.

### Windows-only tests (no CI to enforce them)

`internal/sandbox/restricted/` and `internal/diagnostic/wct/` carry
`//go:build windows` test files (~15 files) that only compile and run
on a Windows host. Because this project has no CI (see "Cutting a
Release" below), nothing mechanically blocks a merge that breaks
them. **Any PR touching either directory must be manually verified
with `go test ./...` on a real Windows host before merge** — a
Linux/macOS-only `go test` run silently skips this coverage.

### Running the e2e suite

`make e2e` runs the integration suite against built binaries. On
Windows hosts the suite covers restricted-token session creation,
DACL DENY stamping on sensitive paths, signal forwarding, and the
daemon IPC round-trip. On macOS / Linux it covers the seatbelt /
bubblewrap backends.

Pre-flight checklist before running e2e locally:

```bash
# 1. Build fresh binaries — e2e shells out to ./bin/dizgin and ./bin/dizgind
make build

# 2. (Windows) scan for and repair any DACL drift from previous runs
dizgind heal

# 3. Run, with the Windows test runner gated on the [e2e] label
make e2e
```

Some e2e cases are gated on real tools being installed (e.g. claude,
aider). Missing tools cause a `t.Skip`, not a failure. This repo runs
no CI — run the full suite locally on Windows with the gated tools
installed before merging.

No coverage targets are enforced. Focus on testing critical paths and adding regression tests for every bug fix.

## Commit Format

[Conventional Commits](https://www.conventionalcommits.org/) required:

```
type(scope): short description

Optional body. Wrap at 72 chars.
```

Types: `feat` `fix` `chore` `docs` `test` `ci` `refactor` `perf`

- `feat`: new user-facing capability → minor version bump
- `fix`: corrects broken behavior → patch bump
- `feat!` / `fix!`: breaking change → major bump
- All others: no version bump

**Scope** = affected module (e.g. `sandbox`, `daemon`, `config`, `netfilter`).

**Anti-patterns:** Don't use `feat` for internal refactors. Don't use `fix` for config/CI changes.

## Pull Request Guidelines

- One logical change per PR
- No CI runs — run all gates locally before merging: `go vet`, `golangci-lint`, `go test -race`, `go build` (windows/linux/darwin)
- For Windows-only changes: ensure build tags (`//go:build windows`) are correct
- New features: include tests
- Bug fixes: include regression test

## Branch Naming

```
feat/<short-description>
fix/<short-description>
chore/<short-description>
docs/<short-description>
```

## Cutting a Release (manual — no CI)

This project follows a no-CI policy; releases are cut manually by a maintainer.

### Prerequisites

```bash
make tool-install   # installs golangci-lint, govulncheck, goreleaser
```

### Pre-release gate

Run all gates locally and confirm they all pass before tagging:

```bash
make fmt            # gofmt -w -s
make lint           # go vet + golangci-lint
make test           # go test -race -count=1 -parallel 4 ./...
make vuln           # govulncheck ./...
make build          # go build for host platform
make release-snapshot  # goreleaser --snapshot --clean (dry-run, writes dist/)
```

Inspect `dist/` to verify the 5 target archives (windows/amd64, darwin/amd64,
darwin/arm64, linux/amd64, linux/arm64) and `checksums.txt` are present.

### Tag and release

```bash
# 1. Create and push the semver tag (triggers GoReleaser)
git tag v0.1.0
git push origin v0.1.0

# 2. Run GoReleaser (requires GITHUB_TOKEN with write:packages + contents scope)
export GITHUB_TOKEN=<your-token>
goreleaser release --clean

# 3. Verify the GitHub release at https://github.com/sungurerdim/dizgin/releases
#    - 5 platform archives + checksums.txt present
#    - SBOM files (*.sbom.spdx.json) attached
#    - Changelog auto-populated from conventional commits
```

### Post-release

- If the Homebrew tap (`dizgin/homebrew-dizgin`) and `HOMEBREW_TAP_TOKEN` are
  provisioned, flip `skip_upload: 'true'` → `skip_upload: 'false'` in
  `.goreleaser.yml` before running GoReleaser.
- Same for the Scoop bucket (`dizgin/scoop-dizgin` + `SCOOP_BUCKET_TOKEN`).

## Reporting Issues

Open a GitHub issue with:
- OS and version
- DIZGIN version (`dizgin version`)
- Minimal reproduction steps
- Full error output (stderr)
