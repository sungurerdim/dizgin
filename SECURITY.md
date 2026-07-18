# Security Policy

## Reporting a Vulnerability

If you discover a security issue in DIZGIN, please **do not file a public
GitHub issue**. Reports are handled privately so a fix can ship before
the details are public.

- **Preferred:** open a private advisory at
  <https://github.com/sungurerdim/dizgin/security/advisories/new>.
- **Alternate:** email the maintainer at <sungurerdim@gmail.com>
  with `[dizgin security]` in the subject line.

Please include enough detail for us to reproduce the issue: affected
version (`dizgin --version`), platform, sandbox backend (restricted token /
Seatbelt / bubblewrap), reproduction steps, and the expected vs.
observed behaviour.

We will acknowledge receipt within **3 business days** and aim to
provide a remediation timeline within **10 business days**.

## Supported Versions

DIZGIN is pre-1.0. Until the first stable release, only the `main` branch
receives security fixes; downgrading to an older tag is not supported.

| Version | Supported          |
|---------|--------------------|
| `main`  | :white_check_mark: |
| `<0.1`  | :x:                |

## Threat Model

For a complete description of DIZGIN's security guarantees — including the
two red lines (sensitive credential isolation via DENY ACEs, native experience),
the defense layers (restricted token + Medium IL + Job Object + DACL DENY on
Windows, Seatbelt on macOS, bubblewrap on Linux), and the no-fallback policy — see
[`docs/SECURITY.md`](docs/SECURITY.md).

## Scope

In scope:

- Sandbox escapes (host filesystem, host network, host processes).
- Privilege escalation through dizgin, dizgind, or the restricted-token
  sandbox lifecycle (DACL DENY bypass, IL manipulation).
- Credential exfiltration paths (SSH agent, API keys, GitHub tokens).
- Daemon IPC misuse (named pipe / unix socket).
- WFP filter bypass or manipulation (Windows network enforcement).

Out of scope:

- Denial of service against the host machine via legitimate sandbox
  resource use (covered by `resources.timeout` / `resources.memory_mb`
  limits, which the user is expected to configure).
- Vulnerabilities in the AI tools themselves (claude-code, codex,
  cursor, etc.) — please report those upstream.
