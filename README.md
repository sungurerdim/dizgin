# DIZGIN

[![Release](https://img.shields.io/github/v/release/sungurerdim/dizgin?include_prereleases&sort=semver)](https://github.com/sungurerdim/dizgin/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go)](go.mod)

**Take the reins.**

dizgin (Turkish for *rein*) minimizes the risk of running AI coding tools with full host access — real OS-native sandboxing, seamless native experience, zero containers.

Two non-negotiable red lines:

- **R1 — Sensitive credential isolation.** A hardcoded DENY-list of 19 high-value credential surfaces (`.ssh`, AWS keys, `.gnupg`, browser cookies, DPAPI vault, and more) receives DACL DENY ACEs on session start; everything else is governed by the user's natural NTFS/POSIX permissions. If isolation can't be established `dizgin` refuses to run — no silent fallback.
- **R2 — Native experience.** Same paths in & out (`host_path == guest_path`), native PTY (ConPTY on Windows), native colors, native shell, named pipes, MCP servers, git integration — all functional. Your tool can't tell it's sandboxed.

**2 binaries. 28 tools. 0 containers.** Restricted token + Medium IL (Windows) / Seatbelt (macOS) / bubblewrap (Linux) — production-tested userland sandboxing made tool-aware.

## Problem

AI coding tools (Claude Code, Codex, Aider, Gemini CLI, OpenCode) run with full host access. This creates two critical risks:

1. **Destructive commands** — `rm -rf /`, accidental file deletion, unauthorized config changes
2. **Credential leaks** — SSH keys, API tokens, git credentials can escape the sandbox

Docker-based solutions introduce path translation issues, FUSE complexity, build overhead, and credential passthrough difficulties.

## Solution

**dizgin** uses platform-native OS sandboxing — no containers, no VMs, no path translation.

| OS      | Backend                                    | Mechanism                                                                    |
|---------|--------------------------------------------|------------------------------------------------------------------------------|
| Windows | Restricted token + Medium IL + Job Object  | `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` + DACL DENY on 19 credential surfaces + per-child DEP/ASLR/ACG-OFF mitigations |
| macOS   | Seatbelt                                   | `sandbox-exec` kernel-MAC policy                                             |
| Linux   | bubblewrap                                 | User namespace + seccomp-BPF, R1 cover-mounts (allowlist network policy not yet enforced — fails fast, no fallback) |

**Security model:** two non-negotiable red lines — (R1) sensitive credential isolation via DACL DENY ACEs on 19 hardcoded surfaces and (R2) native experience. Single backend per platform; sandbox creation either succeeds or fails fast — there is no silent fallback to a less-secure mode. See [docs/SECURITY.md](docs/SECURITY.md) for the full threat model.

## Architecture

Two binaries, clear separation of concerns:

| Binary     | Role                                                              |
|------------|-------------------------------------------------------------------|
| `dizgin`      | Pure sandbox wrapper — runs a command in an isolated process      |
| `dizgind`  | Orchestration daemon — session registry, credential discovery, WFP network enforcement |

## Install

### Windows

```powershell
irm https://raw.githubusercontent.com/sungurerdim/dizgin/main/scripts/install.ps1 | iex
```

### macOS / Linux

```bash
curl -fsSL https://raw.githubusercontent.com/sungurerdim/dizgin/main/scripts/install.sh | sh
```

The installer scans your existing `PATH` for a writable directory and installs there. It **never modifies PATH**.

### Setup

No host-side setup. Install and run.

iter6's restricted token preserves `SeChangeNotifyPrivilege` so NTFS
bypass-traversal works under the user's natural ACL — MSYS2 / Cygwin
tools (`git`, `bash`) inside `dizgin` resolve `getcwd()` through the
user-profile chain without any explicit grant on volume roots. macOS
Seatbelt and Linux bwrap need no setup either; both ship with the OS.

The `dizgind` daemon (Windows) still asks for UAC once when it starts
up — that's only to bind the named pipe with a SYSTEM-owned security
descriptor. After the first `dizgind start`, the daemon runs in the
background and your `dizgin` sessions launch with no further prompts.

### Migrating from earlier builds

- Mount-list YAML schema is unchanged. `force` and `persistent` on
  `sandbox.Mount` (Go-level) are deprecated and ignored at runtime.
- The web dashboard (`dizgind --web`) and TUI (`dizgind tui`) were
  retired. Use `dizgind status --json` for tooling or `dizgind status`
  for a tabwriter table.
- `dizgin unstamp` / `dizgin audit-low` / `dizgind setup` are gone. If you
  have a stale `%ProgramData%\dizgin\setup-marker.json` from an old
  install, it's harmless — nothing reads it any more. Safe to delete.
- The 5-way exit access prompt was replaced by `dizgin add-path <path>`.
  After a "tool referenced paths" hint at session end, run that
  command for any path you want exposed next run.

## Quick Start

```bash
# Run Claude Code in a sandbox (your current directory becomes the workdir)
dizgin claude

# With a custom workdir
dizgin -w /path/to/project claude

# Pass environment variable overrides
dizgin ANTHROPIC_API_KEY=sk-... claude

# Disable PTY (use plain pipes — for scripting and CI)
dizgin --no-pty claude --help
```

## Supported Tools (28 built-in profiles)

DIZGIN ships with profiles for 28 popular tools. Unknown tools work via auto-detection.

| Tool | API Keys |
|------|----------|
| Aide | `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `AIDE_API_KEY` |
| Aider | `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY` |
| Amazon Q | AWS credentials |
| Augment | `AUGMENT_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` |
| Bolt.new | `ANTHROPIC_API_KEY` |
| Claude Code | `ANTHROPIC_API_KEY` |
| Cline | `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `CLINE_API_KEY`, `OPENROUTER_API_KEY` |
| Codex | `OPENAI_API_KEY` |
| Cody | `SRC_ACCESS_TOKEN` |
| Continue.dev | `OPENAI_API_KEY` |
| Cursor | `OPENAI_API_KEY` |
| Devin | `DEVIN_API_KEY` |
| Gemini CLI | `GEMINI_API_KEY`, `GOOGLE_API_KEY` |
| GitHub Copilot | `GITHUB_TOKEN` |
| GPT-pilot | `OPENAI_API_KEY` |
| Lovable | `OPENAI_API_KEY` |
| Mentat | `OPENAI_API_KEY` |
| OpenCode | `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` |
| Plandex | `OPENROUTER_API_KEY` |
| Qodo | `QODO_TOKEN` |
| Roo Code | `ANTHROPIC_API_KEY` |
| SWE-agent | `OPENAI_API_KEY`, `GITHUB_TOKEN` |
| Sweep | `GITHUB_TOKEN` |
| Tabnine | `TABNINE_API_KEY` |
| v0 | `VERCEL_TOKEN` |
| Void Editor | `OPENAI_API_KEY` |
| Windsurf | `CODEIUM_API_KEY` |
| Zed | `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `ZED_CLIENT_SIDE_AI_API_KEY` |

Every tool runs inside the same per-platform sandbox with **credential surface isolation** (DENY ACEs on 19 sensitive paths) and natural NTFS/POSIX access everywhere else — no per-tool sandbox mode toggles, no exceptions. Network policy and credential modes are configured globally (see [Configuration](#configuration)).

**Unknown tools:** Auto-detected via convention — `~/.toolname` config dir, `TOOLNAME_API_KEY` env var. No config needed.

### Custom tool profiles

Add a YAML file to `~/.dizgin/profiles/` or your project's `dizgin.yaml`:

```yaml
# ~/.dizgin/profiles/my-tool.yaml
name: my-tool
config_dirs:
  - "~/.my-tool"
env_keys:
  - MY_TOOL_API_KEY
```

Or inline in project config:
```yaml
# dizgin.yaml
tools:
  my-tool:
    config_dirs: ["~/.my-tool"]
    env_keys: ["MY_TOOL_API_KEY"]
```

## Configuration

Search order: `--config flag` → `<workdir>/dizgin.yaml` → `<workdir>/.dizgin.yaml` → `~/.config/dizgin/config.yaml` → built-in defaults.

```yaml
# ~/.config/dizgin/config.yaml
network:
  policy: open          # open | allowlist | blocked
  allowlist:
    - api.anthropic.com
    - api.openai.com
    - registry.npmjs.org
    - github.com

resources:
  memory_mb: 0          # 0 = unlimited
  cpu_percent: 0
  max_pids: 0
  timeout: 0            # Go duration, e.g. "2h"

credential:
  ssh_agent: true
  git_identity: true
  github_token: true
```

See [docs/CONFIG.md](docs/CONFIG.md) for the full schema.

### Granting access to a new path

A tool referencing a path outside its mounts prints a hint at session
end. Run `dizgin add-path <path>...` to add it to that tool's profile
for next run (`--ro` for read-only, `--tool <name>` to target a
different profile than `$DIZGIN_TOOL`).

`--suggest` prints a recommended mode per path instead of writing
anything — heuristic by default, enriched with a single Claude Haiku
call when `$ANTHROPIC_API_KEY` is set. That call sends each path
(which may reveal your OS username), its kind, and a few derived
booleans to `api.anthropic.com` — never file contents. Set
`DIZGIN_NO_SUGGEST=1` for heuristic-only / air-gapped use, or
`DIZGIN_SUGGEST_MODEL` to pin a different model.

## Exit Codes

| Code  | Meaning                        |
|-------|--------------------------------|
| 0     | Tool exited successfully       |
| 1     | Tool exited with error         |
| 126   | Tool binary not found in PATH  |
| 127   | Sandbox backend not available  |
| 128+N | Tool killed by signal N        |

## dizgind (daemon)

```
dizgind start             # start daemon in background
dizgind start --foreground  # daemon in foreground (debugging)
dizgind status            # show active sessions (tabwriter table)
dizgind status --json     # machine-readable JSON
dizgind stop              # graceful daemon shutdown
dizgind heal              # DACL drift scan (Windows); --apply to revoke
dizgind version           # print version
dizgind completion bash   # generate shell completion (bash|zsh|fish|powershell)
```

## Development

```bash
make build   # build bin/dizgin.exe and bin/dizgind.exe
make test    # go test -race -count=1 ./...
make lint    # go vet ./... + golangci-lint
make fmt     # gofmt -w -s .
make tidy    # go mod tidy
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, testing strategy, and PR expectations.

## Tech Stack

| Component   | Technology                  |
|-------------|-----------------------------|
| Language    | Go 1.25+                    |
| CLI         | spf13/cobra                 |
| Config      | spf13/viper                 |
| Windows PTY | ConPTY (manual syscalls)    |
| Unix PTY    | creack/pty                  |
| Build       | GoReleaser v2               |

## Troubleshooting

- **"dizgin: tool not found"** (exit 126) — The tool binary is not in your `PATH`. Verify with `which <tool>` or `where <tool>` (Windows).
- **"dizgin: sandbox backend unavailable"** (exit 127) — Windows: the restricted-token backend requires Windows 8 or newer. macOS: Seatbelt requires `sandbox-exec` in `PATH`. Linux: bubblewrap requires user-namespace support and the `bwrap` binary.
- **"dizgin: daemon not running"** — Start `dizgind` first. The daemon must be running for IPC features (suspend/resume, session list).
- **Linux network allowlist refuses to start** — `network.policy: allowlist` is not yet enforced on Linux and always fails at `Create()` (no silent open-network downgrade); filtered egress needs a veth/NAT or userland-proxy layer, tracked on the roadmap. Use `network.policy: blocked` for strict denial or `open` for unrestricted access.

## FAQ

### How is DIZGIN different from running my AI tool in Docker?
DIZGIN uses platform-native OS sandboxing (restricted token + Medium IL on Windows, Seatbelt on macOS, bubblewrap on Linux) instead of a container. No image, no path translation. The tool sees the same paths it would see without a sandbox — a hardcoded DENY-list of 19 credential surfaces is blocked; everything else follows natural OS permissions. Cold start under 300 ms vs Docker's 2-5 s.

### What's the threat model?
Two non-negotiable red lines: **R1** — sensitive credential isolation (DENY ACEs on 19 hardcoded credential surfaces; everything else governed by natural NTFS/POSIX rights); **R2** — native experience (`host_path == guest_path`, native PTY, native colors). If the OS sandbox can't be established, `dizgin` refuses to run. No silent fallback. Full model in [docs/SECURITY.md](docs/SECURITY.md).

### Does it work with my AI tool?
28 tools have built-in profiles. Unknown tools auto-detect via the `~/.toolname` + `TOOLNAME_API_KEY` convention. Custom profiles take ~10 lines of YAML.

### Can the sandbox be bypassed?
The same way Edge and Chrome's renderer sandbox can — via a Windows kernel exploit, a Seatbelt MAC bypass, or a Linux user-namespace escape. DIZGIN doesn't claim hypervisor-grade isolation. It claims production-tested userland sandboxing at the same layer Edge and Chrome ship.

### Why not a VM?
Cold start, RAM weight, path translation, broken PTY, broken git integration. The native sandbox is sufficient for AI coding tools because the threat is "untrusted code in a trusted process," not "untrusted kernel."

### Can I contribute a profile for $TOOL?
Yes. PR a YAML file to `profiles/`. Existing profiles are good templates. Auto-detect catches most tools without a profile, but a hand-written one always works better.

## License

MIT — see [LICENSE](LICENSE).
