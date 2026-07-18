# Troubleshooting

## Windows: DENY ACE stamp failed

**Symptom:** `dizgin claude` exits with `restricted: stamp sensitive path C:\Users\<user>\.ssh: access denied` or similar.

**Cause:** `SetNamedSecurityInfo` on the sensitive SSOT path returned `ERROR_ACCESS_DENIED`. This is unusual — dizgin runs as the same user who owns the path and normally has `WRITE_DAC` permission on their own profile directories. A common trigger is a third-party security product holding an exclusive lock on the DACL of a credential directory.

**Fix:** Check whether another security product is actively managing the directory's ACL. Temporarily disable real-time DACL monitoring for your user profile directories and retry. You can also inspect the current DACL with `Get-Acl -Path "$env:USERPROFILE\.ssh" | Format-List` in PowerShell.

---

## `exit code 127`: Sandbox backend unavailable

**Symptom:** `dizgin: sandbox backend unavailable`

**Cause:** The backend for your OS is missing or not registered.

| OS | Required | Check |
|----|----------|-------|
| Windows | Restricted token backend (advapi32) | Run `dizgin doctor` — the `restricted backend smoke` check will report the failure reason |
| macOS | `sandbox-exec` | `which sandbox-exec` |
| Linux | `bwrap` | `which bwrap` |

---

## `network.policy: allowlist` fails on Linux

**Symptom:** `dizgin` exits with `bubblewrap: network.policy=allowlist is not yet enforced on Linux ...` (this is a plain tool-error exit, code 1 — not the exit-127 "backend unavailable" case above; the bwrap backend itself is available and registered, it's just this one network policy that's unimplemented).

**Cause:** Linux filtered egress is not yet built. A `--unshare-net` namespace has only loopback, so no in-namespace nftables ruleset could reach an allowed host regardless of capability — real per-host egress needs a veth+NAT pair or a userland proxy (pasta/slirp4netns). Rather than silently downgrading to `blocked` (which would also block the intended hosts) or `open` (which would grant everything), `Create()` fails fast.

**Fix:** Use `network.policy: blocked` for strict denial or `open` for unrestricted access — these are the two policies Linux enforces today.

---

## `exit code 126`: Tool not found

**Symptom:** `dizgin: tool not found: claude`

**Cause:** The tool binary is not in `PATH`, or the PATH inside the sandbox differs from the host.

**Fix:** Pass the full path or ensure the tool is on PATH before invoking dizgin:
```bash
dizgin /usr/local/bin/claude --help
# or
export PATH="$PATH:/path/to/tool"
dizgin claude --help
```

---

## Credential not injected (API key missing inside sandbox)

**Symptom:** Tool reports missing API key even though it's set in the host environment.

**Cause:** `dizgin` injects only the known keys for the detected tool. Unknown env vars are not passed through by default.

**Check:** Run `dizgin version` to confirm binary is current. Verify the key is in `credential.api_keys` config or as a recognized env var for the tool (see `docs/CONFIG.md` → Tool Environment Keys).

**Fix (config override):**
```yaml
credential:
  api_keys:
    - MY_CUSTOM_API_KEY
```

---

## SSH agent not forwarded

**Symptom:** `git` or SSH operations inside sandbox fail with "Permission denied (publickey)".

**Cause:** `SSH_AUTH_SOCK` not set or socket not accessible to the container.

**Check:**
```bash
echo $SSH_AUTH_SOCK   # must be non-empty
ls -la $SSH_AUTH_SOCK # must exist
```

**Fix:**
```yaml
credential:
  ssh_agent: true  # default, but confirm config is loaded
```

On Windows, ensure the OpenSSH agent service is running:
```powershell
Get-Service ssh-agent | Set-Service -StartupType Automatic
Start-Service ssh-agent
```

---

## PTY / terminal not working (garbled output, no color)

**Symptom:** Tool output is garbled, raw escape codes visible, or interactive mode doesn't work.

**Cause:** PTY allocation failed, or `--pipe` was passed.

**Check:** The parent terminal must itself be a TTY. Running inside `cmd.exe` without a real PTY may degrade behavior.

**Fix:**
- Use Windows Terminal or a proper PTY-capable terminal
- Don't pipe dizgin output if interactive mode is needed: `dizgin claude` (no `| tee`)
- On Windows, `cmd.exe /c ...` inside container has console handle isolation issues; use `powershell -NonInteractive` or PTY mode

---

## Config file not found

**Symptom:** dizgin uses defaults instead of your config.

**Search order:**
1. `-c <file>` flag (explicit override)
2. `./dizgin.yaml` (current working directory)
3. `$XDG_CONFIG_HOME/dizgin/config.yaml` (if `XDG_CONFIG_HOME` is set)
4. `~/.config/dizgin/config.yaml`

**Fix:** Create the file or use `-c /path/to/config.yml`.

---

## `dizgind`: cannot connect to daemon

**Symptom:** `dizgind status` reports "connection refused" or no daemon found.

**Cause:** The daemon is not running.

**Fix:**
```bash
# Start the daemon in a separate terminal:
dizgind start

# Then check status:
dizgind status
```

On Windows, the named pipe is `\\.\pipe\dizgind`. On Linux/macOS: `$XDG_RUNTIME_DIR/dizgind.sock`.

---

## Windows: network allowlist enforcement scope

**Symptom:** A sandboxed tool opens a TCP connection to an IP literal (no DNS lookup) that is not on the allowlist and the connection still succeeds.

**Cause:** The Windows backend enforces `network.policy: allowlist` with a user-mode WFP (Windows Filtering Platform) filter set managed by `internal/netfilter/wfp_windows.go`. Because dizgin runs non-elevated, the WFP filters are installed by the elevated `dizgind` daemon via the `wfp_apply`/`wfp_revoke` IPC messages. The filter set creates an app-id-scoped block at `ALE_AUTH_CONNECT_V4/V6` and a per-IP permit for each allowlisted hostname's resolved addresses.

This is **accidental-egress protection**, not hostile-tool-grade isolation: a same-SID process can delete the WFP filters directly. A kernel-mode callout driver (ROADMAP #1) is the path to hostile-tool enforcement. In the interim:

**CIDR entries** in the allowlist are not yet supported — they are logged and skipped, not silently applied.

**Mitigations for the current tier:**
- Use `network.policy: blocked` for zero-egress sessions.
- Run dizgin behind a host firewall / egress proxy that also applies IP filtering.
- Set `DIZGIN_NO_WFP=1` to revert to advisory-only mode (no WFP filters installed); useful for diagnosing WFP-related errors.

The dizgind daemon logs every WFP filter install/revoke event at INFO level.

---

See "`network.policy: allowlist` fails on Linux" above — Linux does not
silently downgrade to open network; it refuses to start the session.
