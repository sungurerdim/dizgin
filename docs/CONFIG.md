# dizgin — Configuration Reference

Configuration is loaded in the following priority order (highest first):

1. CLI flags (`-c <file>`)
2. `dizgin.yaml` or `.dizgin.yaml` in the project workdir
3. `~/.config/dizgin/config.yaml` (or `$XDG_CONFIG_HOME/dizgin/config.yaml`)
4. Built-in defaults

---

## 3-tier R model (iter4, retained as a mount classifier)

dizgin assigns every mount to one of three tiers. The Windows restricted
backend (iter6) uses the tier for audit-log clarity and Seatbelt / bwrap
use it directly to drive their RO/RW bind decisions. Profile authors
do not declare the tier directly; it is derived from the YAML field
the mount comes from.

| Tier | YAML source | Mode | Backend behavior |
|------|-------------|------|------------------|
| R1-A `workdir` | implicit (current dir or `-w` flag) | RW | On restricted: covered by the user's natural NTFS perms (no DACL touch needed). On Seatbelt / bwrap: bind-mounted RW. |
| R1-B `declared_rw` | `filesystem.read_write`, `config_dirs`, `mcp_dirs`, `tool_deps` (RW), npm cache | RW | On restricted: covered by user's natural NTFS perms unless intersecting the sensitive SSOT. On Seatbelt / bwrap: bind-mounted RW. |
| R1-C `declared_ro` | `filesystem.read_only`, `lib_deps`, `tool_deps` (RO) | RO | On restricted: user's natural NTFS RO already applies for system / Program Files trees; the classifier tag stays for audit clarity. On Seatbelt / bwrap: bind-mounted RO. |
| `path` / `system` | host `$PATH` + OS-managed dirs | RO | Skipped — covered by the user's natural NTFS rights on Windows, system-paths-allow on Seatbelt, system bind on bwrap. |
| R1-DENY (sensitive) | hardcoded SSOT in `internal/security/sensitive_paths_windows.go` (`.ssh`, `.aws/credentials`, `.gnupg`, DPAPI vault, browser cookies, …) | denied | On restricted: DACL DENY ACE for the user SID with OI+CI inheritance, revoked on session exit. On Seatbelt / bwrap: covered by the SBPL / bwrap mount policy (no DACL primitive on those platforms). |

Common decision: when adding a path, ask "does the tool need to write
here?" Yes → `filesystem.read_write`. No → `filesystem.read_only`.
Most editor / language-server config dirs land in RW; runtime library
trees (`/opt/python/lib`, Node's lib dir) land in RO.

### Deprecated fields (iter4)

`force:` and `persistent:` on `sandbox.Mount` are deprecated. They are
silently ignored at runtime — the iter6 restricted backend's DACL DENY
model uses the sensitive SSOT (not a per-mount stamp), so the old
boolean overrides have no effect. The fields remain on the struct for
schema round-trip; planned removal at the next config-breaking bump.

Migration: nothing to do for YAML profiles — neither flag is part of
the on-disk schema. Audit any Go code that constructs `sandbox.Mount`
values directly and drop the deprecated fields when convenient.

---

## Full Schema

```yaml
# Config file version. Must be 1.
version: 1

# The AI tool binary name (optional — can be specified on the command line).
tool: claude

# Working directory override (optional — defaults to the current directory).
workdir: /path/to/project

# Filesystem isolation settings.
filesystem:
  # Additional paths to mount read-write inside the sandbox.
  read_write: []

  # Additional paths to mount read-only inside the sandbox.
  read_only: []

  # Size of the temporary directory allocated for the session.
  # Uses OS temp dir on Windows; tmpfs on Linux.
  tmp_size: 256m

  # If true, all files written to the sandbox temp dir are overwritten with
  # zeros before deletion. Prevents data recovery tools from recovering
  # session artefacts.
  zero_residue: false

# Network access policy.
network:
  # Policy options:
  #   open      — unrestricted outbound access (default)
  #   allowlist — only hosts in the allowlist can be reached
  #   blocked   — no outbound network access
  policy: open

  # Required when policy=allowlist. List of hostnames or CIDR ranges.
  allowlist:
    - api.anthropic.com
    - api.openai.com
    - registry.npmjs.org
    - github.com

# Security hardening flags. Linux-only — no-op on Windows + macOS where
# the restricted backend (restricted token + Medium IL) and Seatbelt
# achieve the equivalent natively at sandbox creation time. Kept in
# config so a single YAML works everywhere.
security:
  # Prevents the sandbox process from gaining new privileges
  # (PR_SET_NO_NEW_PRIVS). On Linux, --unshare-user already provides this.
  # (Default: true)
  no_new_privileges: true

  # Drop all Linux capabilities. On Linux, --unshare-user already yields
  # cap=0 in the new namespace. (Default: true)
  drop_all_caps: true

# Resource limits. Set to 0 to disable the limit.
resources:
  # Maximum resident memory in mebibytes (e.g. 4096 = 4 GB).
  # Enforced via Job Object on Windows and cgroups on Linux. NOT enforced
  # on macOS: the kernel rejects setrlimit(RLIMIT_AS, <finite>)
  # unconditionally (only RLIM_INFINITY is accepted) — the same reason
  # bash's `ulimit -v` reports "not supported" there. The field is parsed
  # but has no effect on that backend today.
  memory_mb: 0

  # CPU share cap as a percentage (1–100). 0 = unlimited.
  # Enforced via Job Object on Windows and cgroups on Linux. Not enforced
  # on macOS (rlimit has no CPU-percent equivalent); the field is parsed
  # but ignored there.
  cpu_percent: 0

  # Maximum number of processes inside the sandbox. 0 = unlimited.
  max_pids: 0

  # Session timeout (Go duration string, e.g. "2h", "30m"). Default 30m
  # caps runaway loops; set 0 to disable.
  timeout: 30m

# Privilege dropping (Windows: unused; Linux/macOS: run as this user).
privileges:
  run_as_user: ""

# Credential forwarding.
credential:
  # Forward the host SSH agent socket into the sandbox. (Default: true)
  ssh_agent: true

  # Environment variables to inject (in addition to the well-known set).
  # The scan always includes ANTHROPIC_*, OPENAI_*, GEMINI_*, etc.
  api_keys: []

  # Read git user.name and user.email from the host global git config. (Default: true)
  git_identity: true

  # Resolve GITHUB_TOKEN from env / gh CLI / git credential helper. (Default: true)
  github_token: true

  # Credential providers to enable (e.g. "keychain", "credential-manager", "secret-tool").
  # Empty = auto-detect based on platform.
  providers: []

  # HashiCorp Vault mount and path for secret retrieval (optional).
  vault_mount: ""
  vault_path: ""

# Resource metrics collection.
monitor:
  # Collection depth: "basic" (memory, CPU, PIDs), "detailed" (+ I/O, disk),
  # or "full" (+ threads, handles, process tree). Default: "basic".
  level: basic

  # Collection interval. Default: "10s".
  interval: 10s

# Audit logging (opt-in).
audit:
  # Enable JSON-L audit log. Default: false.
  enabled: false

  # Max log file size in MiB before rotation. 0 = unlimited.
  max_size_mb: 0

# Inline tool profile overrides. See profiles/*.yaml for full syntax.
tools:
  my-tool:
    config_dirs: ["~/.my-tool"]
    env_keys: ["MY_TOOL_API_KEY"]
```

---

## Profile YAML — `ipc:` field (informational only)

Older tool profiles (in `profiles/*.yaml`) carry an `ipc:` field with
values `stdio`, `pipe`, or `socket`. **This field has no runtime effect
on current builds.** The active sandbox backend is selected purely by
platform — Windows uses the restricted backend (restricted token +
Medium IL + Job + per-child mitigation policy + DACL DENY on the
sensitive SSOT), macOS uses Seatbelt, Linux uses bubblewrap — and
there is no longer an alternative path the field could select.

The field is parsed-and-ignored to keep older profile YAML files loading
cleanly. Contributors writing new profiles may set it to a value that
documents how the tool actually talks to the host (a useful hint for
readers), but dizgin will neither validate nor act on the choice.

---

## Profile YAML — `compatibility:` block (iter5 + iter6)

Per-tool toggles for dizgin's defence-in-depth hardening. Each field is
optional and defaults to "use dizgin's compiled default for this runtime"
when omitted. Bun-runtime tools (Claude Code, Bun CLI shipped as a SEA)
automatically inherit the layout that keeps the SEA extract working —
`temp_override: true` and `handle_list_allowlist: true`.

```yaml
compatibility:
  # iter5 L1 — per-session TEMP / TMP / TMPDIR redirect to the
  # restricted backend's scratch dir so Bun-class self-extracting
  # runtimes don't leak into the host's %TEMP%. Default: true.
  # Emergency: DIZGIN_NO_TEMP_OVERRIDE=1.
  temp_override: true

  # iter5 L2 — PROC_THREAD_ATTRIBUTE_HANDLE_LIST PTAL entry so only
  # the three stdio handles inherit into the child (instead of every
  # inheritable handle in dizgin's process table). Default: true.
  # Emergency: DIZGIN_NO_HANDLE_LIST=1.
  handle_list_allowlist: true

  # Forward-looking — dizgin does not currently emit either mitigation
  # policy. Reserved YAML field so future hardening passes can ship
  # without breaking existing profiles' strict-mode parse.
  allow_dynamic_code: true
  allow_low_label_images: true

  # iter6 Phase C — nested mitigation_policy block. Only one toggle
  # today; nested shape so the next process-mitigation toggle slots
  # in without another YAML shape change.
  mitigation_policy:
    # Opt-in only. Sets PROCESS_CREATION_MITIGATION_POLICY_
    # BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON when spawning the child.
    # Breaks any tool that loads third-party DLLs by design — leave
    # OFF unless you specifically want the extra hardening.
    block_non_microsoft_binaries: false
```

---

## Permission Learning — `~/.dizgin/permissions/<tool>.yaml` (iter6 Phase D)

The Windows restricted backend's DACL DENY model has a known tension:
if a tool legitimately needs one of the sensitive SSOT paths (e.g. a
tool whose purpose is to audit `~/.ssh/known_hosts`), the default DENY
blocks it. iter6 Phase D adds an opt-in escape valve via a per-tool
permission profile.

### Workflow

1. Run `dizgin --learn -- <tool>`. The DENY stamps stay in place but dizgin
   wraps the child's stderr with an access-denial recorder.
2. On exit, dizgin prints a summary and asks `[rw/ro/deny/skip]` for each
   captured path.
3. Decisions are persisted atomically to `~/.dizgin/permissions/<tool>.yaml`.
4. The next normal run (no `--learn`) auto-loads the file; listed paths
   are exempted from the sensitive-SSOT DENY pass.

### Schema

```yaml
version: 1
tool_name: claude
tool_path: C:\Users\me\AppData\Local\Programs\Claude\claude.exe
learned_at: 2026-05-18T10:30:00Z

overrides:
  rw: []                                 # full RW exemption
  ro:                                    # RO exemption
    - 'C:\Users\me\.aws\credentials'
  deny:                                  # explicit DENY (tool-specific,
                                          # even if not in the SSOT)
    - 'C:\Users\me\projects\private-keys'
```

### Notes

- **Auto-load default ON.** The user opted in once; re-running
  `dizgin -- <tool>` doesn't require re-confirmation. Re-enter the prompt
  loop with `dizgin --learn`.
- **TTY required.** Piped / cron stdin auto-defaults every entry to
  `skip` so the prompt cannot hang an unattended job. The captured paths
  still appear in the summary above the prompt.
- **High-risk path warning.** When the prompt offers a credential-
  shaped path (`.ssh`, `.aws/credentials`, DPAPI vault, browser cookies,
  …) it prints an extra `[!] this path holds credential material`
  warning before reading the choice.
- **Tool-path mismatch warning.** The profile records the tool's
  absolute path at decision time. If the binary later moves (e.g. after
  a reinstall), the next normal run prints a warning so the user can
  re-confirm the saved decisions.
- **Reset by deletion.** `rm ~/.dizgin/permissions/<tool>.yaml` reverts
  the tool to the SSOT default.

---

## Per-tool Defaults

DIZGIN automatically mounts the tool's config directories (R/W) and runtime directories (R/O):

| Tool     | Config paths (R/W)                                                                                                              | Runtime paths (R/O)                                                   | Env keys                                              |
|----------|---------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------|-------------------------------------------------------|
| claude   | `~/.claude`, `~/.claude.json`                                                                                                   | `%APPDATA%/Claude/claude-code`, `claude-code-vm`, `vm_bundles` (Win) | `ANTHROPIC_API_KEY`, `ANTHROPIC_BASE_URL`             |
| codex    | `~/.codex`                                                                                                                      | —                                                                     | `OPENAI_API_KEY`, `OPENAI_BASE_URL`                   |
| aider    | `~/.aider`, `~/.aider.conf.yml`, `~/.aider.models.yml`, `~/.aider.model.settings.yml`, `~/.aider.model.metadata.json`          | —                                                                     | `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `AZURE_OPENAI_API_KEY`, `GROQ_API_KEY` |
| gemini   | `~/.gemini`                                                                                                                     | —                                                                     | `GEMINI_API_KEY`, `GOOGLE_API_KEY`                    |
| opencode | `~/.config/opencode` (Linux/macOS), `%APPDATA%/opencode`, `%LOCALAPPDATA%/opencode` (Windows)                                  | —                                                                     | `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY` |

Unknown tools are auto-detected via convention: `~/.toolname` config dir, `TOOLNAME_API_KEY` env var.

See `profiles/*.yaml` for the full set of 24 built-in tool profiles.

---

## Exit Codes

| Code  | Meaning                              |
|-------|--------------------------------------|
| 0     | Tool exited successfully             |
| 1     | Tool exited with error               |
| 126   | Tool binary not found in PATH        |
| 127   | Sandbox backend not available        |
| 128+N | Tool killed by signal N              |
