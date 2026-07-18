# e2e — Integration test suite

End-to-end integration tests that exercise the real `dizgin` and `dizgind`
binaries against an actual sandbox backend. Build-tagged with
`integration` so `go test ./...` does **not** pick them up by default —
they need infrastructure (dizgind on PATH, an interactive Windows desktop
session with write access to the user profile, …) that not every
machine running the unit suite will have.

## How to run locally

```bash
make e2e
```

The `make e2e` target builds fresh `dizgin` / `dizgind` binaries, copies
them into `tests/e2e/testdata/` (where the suite resolves them), and
invokes:

```bash
go test -tags=integration -timeout 300s ./tests/e2e/...
```

The cleanup step removes the staged binaries on success so a stray
copy does not get committed by accident.

## Test environment

Every test in this directory has the build constraint
`//go:build integration` (and most also `windows`). `tests/e2e/main_test.go`
sets `DIZGIN_NO_DAEMON_AUTOSTART=1` so the suite startup does not block
waiting for a dizgind daemon that may not be present.

| Variable                    | Effect                                                |
|-----------------------------|-------------------------------------------------------|
| `DIZGIN_NO_DAEMON_AUTOSTART`  | `1` ⇒ dizgin skips auto-spawning dizgind                 |
| `DIZGIN_DEBUG`                | `1` / `all` ⇒ verbose framework output                |
| `CI`                        | non-empty ⇒ missing `dizgin.exe` becomes a hard failure  |

## Skip behaviour

When the binary referenced by `copBin(t)` is missing, the test:

- **Locally:** logs the build hint and `t.Skip()`s.
- **In CI** (`CI` env variable set): hard-fails so a misconfigured
  `make e2e` step is caught instead of silently passing the suite.

## Test inventory

| File                                       | Build tags          | Notes                                             |
|--------------------------------------------|---------------------|---------------------------------------------------|
| `basic_test.go`                            | `integration`       | echo / workdir / exit-code / tool-not-found       |
| `basic_unix_test.go`                       | `integration && !windows` | parallel test set for Linux + macOS               |
| `access_prompt_test.go`                    | `integration`       | access telemetry "missing path" report           |
| `network_allowlist_windows_test.go`        | `windows && integration` | DNS allowlist enforcement                        |
| `parallel_windows_test.go`                 | `windows && integration` | concurrent dizgin sessions stamping the same path   |
| `smoke_claude_windows_test.go`             | `windows && integration` | full Claude bring-up scenario                    |
| `stamp_delegation_windows_test.go`         | `windows && integration` | broker stamp + revoke RPC                        |
| `suspend_resume_windows_test.go`           | `windows && integration` | dizgind suspend/resume IPC                       |

## Adding a new e2e test

1. Place the file under `tests/e2e/` with a `_test.go` suffix.
2. First line of the file:
   ```go
   //go:build integration
   ```
   add `&& windows` if it requires the Windows restricted backend.
3. Use `copBin(t)` to resolve the dizgin binary — never hardcode a path.
4. Use `t.TempDir()` for any host filesystem state — the staging
   sweeper will not clean directories it did not create.
