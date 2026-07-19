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

# Build + install your current local checkout, replacing whatever
# dizgin/dizgind are already on PATH — the day-to-day way to try a
# change for real instead of just running the test suite against it.
make install

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

### `make install`

Builds `dizgin` + `dizgind` from your current checkout, gracefully stops
any running `dizgind`, then installs the fresh binaries:

- **Windows** — `scripts/install.ps1 -LocalBinary bin/dizgin.exe`: kills
  holdout processes, wipes `%ProgramData%\dizgin` state through a single
  elevated subprocess, copies the binaries into place, then also runs
  `dizgind start` under that same UAC prompt — the restricted backend
  needs the elevated daemon running.
- **macOS / Linux** — `scripts/install.sh` in `LOCAL_BINARY` mode: copies
  into the first writable directory already on `PATH` (preferring an
  existing `dizgin` install location, then `/usr/local/bin`,
  `~/.local/bin`, `~/bin`); no elevation needed, and `dizgind` is **not**
  started — `ensureDaemonRunning` is a documented no-op on non-Windows
  (`cmd/dizgin/daemon_check_other.go`: "macOS/Linux sandbox backends
  don't require a daemon"), and `dizgind start` itself blocks in the
  foreground with no self-daemonization there. Only run it yourself, in
  its own terminal, if you specifically need the daemon's session
  management / credential discovery features.

This is distinct from the end-user install one-liners in `README.md` /
`docs/QUICKSTART.md` (`curl ... install.sh | sh`, `irm ... install.ps1 |
iex`), which fetch the **latest published GitHub release**, not your
local build — same underlying scripts, different mode.

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

### Git hooks (pre-commit + pre-push)

The repo ships two hooks under `scripts/git-hooks/`. Wire them into your
local repo with:

```bash
make hooks-install   # sets core.hooksPath to scripts/git-hooks
```

- **pre-commit** (`scripts/pre-commit.sh` / `.ps1`) — fast, runs on every
  commit: `gofmt -l`, `go vet`, and `golangci-lint run --new-from-rev=HEAD`
  scoped to the files you staged.
- **pre-push** (`scripts/pre-push.sh` / `.ps1`) — heavier, runs on every
  push: `gofmt`, full `go vet` + `golangci-lint run`, `make build`
  (typecheck), `make test` (race), `make vuln` (govulncheck), and
  `make e2e`. This is the same gate `make release` relies on to guarantee
  the full check set runs exactly once per release — see "Cutting a
  Release" below.

Bypass either with `git commit --no-verify` / `git push --no-verify` only
when you have a specific reason — opening a draft PR for review is
preferred over pushing known-broken code.

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

This project follows a no-CI policy; releases are cut manually by a
maintainer, via a single gated command.

### Prerequisites

```bash
make tool-install     # installs golangci-lint, govulncheck, goreleaser
make hooks-install     # wires scripts/git-hooks -> core.hooksPath (release
                       # self-installs this too if it's missing)
export GITHUB_TOKEN=<token>   # contents:write (+ packages:write for the
                               # Homebrew/Scoop pushes, if enabled)
```

### Canonical path: `make release`

```bash
make release                # auto-detects the next version
make release TAG=v0.2.0     # or pin it explicitly (pre-releases: TAG=v0.2.0-rc1)
```

This is the only command a maintainer runs day-to-day. It is gated end to
end (`scripts/release.sh`) — any red stage stops everything before
anything reaches origin or GitHub:

1. **Dirty-tree guard** — refuses to run against an unclean working tree;
   only a committed HEAD is ever released.
2. **Gate, exactly once** — resolves the version, tags `HEAD`, then either
   `git push`es the branch + tag together (the `pre-push` hook runs the
   full lint + build(typecheck) + test + govulncheck(dependency-audit) +
   e2e set — installed automatically if `make hooks-install` was never
   run), or, if the branch and tag are already on `origin` (retrying a
   prior failed attempt), runs that identical gate inline instead, since a
   no-op push would never fire the hook.

   Without `TAG=`, the version is auto-detected from Conventional Commits
   since the last pure-semver release tag: any `feat:` → minor bump, any
   `fix:` → patch bump, any `!` (e.g. `feat(config)!:`) or a
   `BREAKING CHANGE:` footer → major bump (highest wins). No prior release
   tag → bootstraps at `v0.1.0`. If every commit since the last tag is
   `chore:`/`docs:`/`refactor:`/`test:`/`ci:`/`style:`, there is nothing
   user-facing to release and the command aborts — pass `TAG=` explicitly
   to force a release anyway. `TAG=` also always wins when given, including
   for pre-release tags (`-rc1` etc.), which auto-detection never proposes
   on its own.

   Before a brand-new auto-detected version is ever tagged, `make release`
   prints the commit list and diffstat since the last release tag and asks
   for an explicit `yes` — this is the guard against shipping a minor/major
   release for a change that's technically `feat:`/`fix:` but not actually
   worth a release (e.g. a trivial two-line tweak); read the summary and
   decide, rather than trusting a size threshold that would just as easily
   block a genuinely release-worthy one-line fix. Set `RELEASE_YES=1` to
   skip the prompt for scripted use; a non-interactive shell without it
   refuses rather than guessing. Resuming an already-tagged prior attempt
   never re-prompts.
3. **Cadence-aware heavy layer** — a gitignored stamp file
   (`.release-heavy-stamp`) tracks the last run; if it's missing or more
   than 7 days old, `make release` also runs a coverage-threshold check
   (>=70%, per the blueprint in `CLAUDE.md`) and a full 5-target
   cross-platform artifact build (`make release-snapshot`) before
   deploying, then refreshes the stamp. Fresh stamps skip this so routine
   releases stay fast.
4. **Deploy** — `goreleaser release --clean`, publishing to GitHub
   Releases (and Homebrew/Scoop if their `skip_upload` flags are off).
5. **Verify-live** — confirms the published tag's remote commit matches
   local `HEAD` and that the release has the expected assets (5 platform
   archives + `checksums.txt`) via `gh`. Deploy is not considered done
   until this is green — a deploy that fails verification is reported as
   "deployed but not verified", not silently swallowed as success.

Because the pre-push hook now runs the full gate, this cost is paid on
*every* `git push` once hooks are installed, not just releases — that is
intentional so a broken commit can never reach `origin`.

### Emergency escape hatch

```bash
make release-raw CONFIRM=yes TAG=v0.2.0
```

Tags, pushes, and runs GoReleaser directly with **no gates at all** — no
dirty-tree check, no lint/test/vuln/e2e, no coverage or cross-platform
build, no verify-live. This exists only for a genuine emergency (e.g. the
gated path itself is broken and a fix must ship now); `CONFIRM=yes` is
required so it can't be run by muscle memory in place of `make release`.

### Post-release

- If the Homebrew tap (`dizgin/homebrew-dizgin`) and `HOMEBREW_TAP_TOKEN` are
  provisioned, flip `skip_upload: 'true'` → `skip_upload: 'false'` in
  `.goreleaser.yml` before running `make release`.
- Same for the Scoop bucket (`dizgin/scoop-dizgin` + `SCOOP_BUCKET_TOKEN`).

## Reporting Issues

Open a GitHub issue with:
- OS and version
- DIZGIN version (`dizgin version`)
- Minimal reproduction steps
- Full error output (stderr)
