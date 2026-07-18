# Quickstart

Get from "I just heard about dizgin" to "my first sandboxed Claude
session" in under 60 seconds.

## 1. Install

### Windows

```powershell
# Download and run the install script from GitHub Releases (recommended):
Invoke-WebRequest https://github.com/sungurerdim/dizgin/releases/latest/download/install.ps1 -OutFile install.ps1
.\install.ps1

# Or download the zip directly and extract dizgin.exe + dizgind.exe to a directory on $PATH:
# https://github.com/sungurerdim/dizgin/releases/latest
```

> **Note:** winget and Homebrew packages are not yet available. Use the GitHub Releases installer above.

### macOS

```bash
# Download and run the install script from GitHub Releases:
curl -fsSL https://github.com/sungurerdim/dizgin/releases/latest/download/install.sh | bash
```

> **Note:** Homebrew tap is not yet available. Use the script above.

### Linux

```bash
# Debian / Ubuntu
curl -fsSL -o dizgin.deb https://github.com/sungurerdim/dizgin/releases/latest/download/dizgin-linux-amd64.deb
sudo dpkg -i dizgin.deb

# Fedora / RHEL
curl -fsSL -o dizgin.rpm https://github.com/sungurerdim/dizgin/releases/latest/download/dizgin-linux-amd64.rpm
sudo rpm -i dizgin.rpm

# Arch
yay -S dizgin-bin

# Manual: download the tarball + drop binaries on $PATH
curl -fsSL https://github.com/sungurerdim/dizgin/releases/latest/download/dizgin-linux-amd64.tar.gz | sudo tar -xzC /usr/local/bin
```

## 2. Verify

```bash
dizgin doctor
```

Expected output:

```
[ OK ] config load — no config file specified; defaults loaded
[ OK ] profiles load — 29 tool profile(s) loaded
[ OK ] daemon reachable — dizgind daemon responsive
[ OK ] disk space — 142387 MiB free at C:\ProgramData\dizgin
[ OK ] restricted backend smoke — restricted Medium-IL token round-trip OK

dizgin doctor: all checks passed.
```

If any check fails, the per-check `hint:` line tells you what to fix.
Re-run `dizgin doctor` after each fix until everything is green.

## 3. First sandboxed session

```bash
# Set your API key (see docs/CONFIG.md for alternatives like ~/.config/anthropic)
export ANTHROPIC_API_KEY="sk-ant-..."

# Run Claude Code inside the sandbox. Working directory == sandbox path.
dizgin claude --print "Hello from inside dizgin"
```

On first run dizgin applies DENY ACEs to the 19 sensitive credential paths
(`.ssh`, `.aws/credentials`, `.gnupg`, browser cookie stores, etc.) via
`SetNamedSecurityInfo`. This is nearly instantaneous. Every subsequent
session re-applies the same DENY set at startup and revokes it on exit.

## 4. Common gotchas

### Git Bash / MSYS2 / Cygwin path conversion

These shells silently rewrite `/c`, `/b`, `/d`-style arguments into
Windows paths (`C:\...`) before they reach dizgin. Two ways out:

```bash
# Option A — disable conversion for the call
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' dizgin cmd /c echo hello

# Option B — use the run subcommand which takes one quoted string
dizgin run "cmd /c echo hello"
```

dizgin emits a one-time warning the first time it spots the conversion
shape. Silence it with `export DIZGIN_NO_SHELL_DETECT=1`.

### Antivirus / EDR interfering with sandbox setup

Some endpoint security products flag dizgin on first run because the
`CreateRestrictedToken` + Job Object pattern matches their "process
isolation framework" detection, or because the DACL modification
(`SetNamedSecurityInfo`) on credential paths triggers a DACL-tamper
alert. Workaround: add `dizgin.exe` and `dizgind.exe` to the AV
allowlist. The binaries ship code-signed (EV cert) so SmartScreen
accepts them out of the box.

### Daemon not running

`dizgin` autostarts `dizgind` on first call. If that fails, run:

```bash
dizgind start
dizgin doctor   # verify
```

## Next steps

- [`docs/CONFIG.md`](CONFIG.md) — `dizgin.yaml` reference
- [`docs/SECURITY.md`](SECURITY.md) — what dizgin protects (and what it doesn't)
- [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) — how dizgin, dizgind, and the sandbox backends fit together
- [`docs/TROUBLESHOOTING.md`](TROUBLESHOOTING.md) — error → fix lookup table

## Where to get help

- File a bug at https://github.com/sungurerdim/dizgin/issues
- Security report: https://github.com/sungurerdim/dizgin/security/advisories/new (private — see SECURITY.md for the disclosure policy)
