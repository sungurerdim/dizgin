# DIZGIN Roadmap

This file tracks **deferred capabilities** removed during iter4 and the
**active R&D** lines that may bring some of them back in a different
shape. Items listed under "Won't do" are explicit non-goals — they exist
here so future contributors do not re-litigate the trade-off.

The iter4 cleanup (2026-05-18) was driven by three observations:

1. DIZGIN's primary user is a developer running `dizgin` from a terminal
   alongside their AI coding tool. Web dashboards and TUIs add surface
   area that audience does not consume.
2. Defense-in-depth layers that depend on userspace enforcement (DNS
   proxy, access-prompt UI) have escape hatches and cognitive costs that
   outweigh their incremental security value.
3. Public 0.1.0 needs a sharper README, fewer subcommands, and a
   binary that boots in <100 ms warm. Every feature on this roadmap
   was a candidate for "now or later" — these are the laters.

---

## Deferred — removed in iter4

### Web dashboard (removed 2026-05-18)

**Was:** `internal/api/` (~1.6K LOC), `--web --port --token` flags on
`dizgind`. HTTP+JSON dashboard for session inspection.

**Why removed:** Never reached beta usage in pilot installs. Adds an
auth token + open port + static asset surface (`static/index.html`)
that AI-coding-tool CLI users don't pull on.

**What replaces it:** `dizgind status --json` plus `dizgin doctor --json`.
The two cover the inspection paths the dashboard's read-only side
exposed.

**Future plan:** A lightweight Prometheus exporter. Single
`/metrics` endpoint, no UI, optional binary. Bind localhost-only;
expose session counts, stamp counts, daemon uptime. Estimated 200 LOC.
Trigger: user demand or a Grafana operator scenario.

### Bubbletea TUI (removed 2026-05-18; `dizgin-tui` retry removed 2026-05-29)

**Was:** `internal/tui/` (~2.3K LOC, 12 files). `dizgind tui`
subcommand with sessions / detail / credentials panes built on
charmbracelet/bubbletea and lipgloss. A second attempt shipped the
same stack as a standalone `cmd/dizgin-tui/` binary (iter7); it was
removed again on 2026-05-29 to keep the base build's dependency tree
minimal until the rest of the platform stabilizes.

**Why removed:** Same niche as the web dashboard. Pulled the entire
charmbracelet dependency tree (bubbletea + lipgloss + x/term + x/ansi
+ cellbuf + displaywidth + uax29 + coninput) into a tool whose user
already has a terminal.

**What replaces it:** `dizgind status` with the tabwriter table.

**Future plan:** TUI v2 as an optional binary `dizgin-tui` — same
charmbracelet stack but ship-or-don't-ship is a download decision, not
a hard dependency. Or a minimal ANSI table written from scratch (~300
LOC) if the dependency tree is the only complaint.

### Userspace DNS allowlist proxy (removed 2026-05-18)

**Was:** `internal/daemon/dnsproxy_windows.go` (~600 LOC). UDP
listener bound to a per-session endpoint; forwarded queries to an
upstream resolver and returned NXDOMAIN for non-allowlisted hosts.

**Why removed:** Bypassable by IP literal. A tool that resolves
`example.com` once and then connects to the cached IP, or that hard-
codes a Cloudflare IP, completely sidesteps the DNS layer. The
illusion of allowlist enforcement was worse than the absence.

**What replaces it (post-iter6):** `network.policy: allowlist` is
advisory only on Windows after iter6 retired the AppContainer
backend (the InternetClient capability gate disappeared with it).
The new `restricted` backend does not enforce network policy
itself; the kernel allowlist below is the real-enforcement path.

**Future plan:** WFP (Windows Filtering Platform) callout driver
allowlist — Q3 2026. Kernel-level filter, IP+port-based, signed
DNS-layer + NETWORK_LAYER simultaneously. Adds an installer
kernel-driver signature requirement; tracked against the public
0.1.x roadmap (not 0.1.0 — too large for the iter6 ship).

### 5-way exit access prompt (removed 2026-05-18)

**Was:** `cmd/dizgin/access_prompt_ui.go` + extended telemetry library
(~13K LOC including tests). At session exit, the user saw a list of
paths the tool tried to reach and could choose RW / RO / Skip / Never
/ Block for each.

**Why removed:** Cognitive load on first session — a wall of paths
right after the tool finished, before the user had context to decide.
Defaults were ambiguous (was the path a config file or a secret?).
Most users hit "skip everything" or kept the prompt deferring
indefinitely.

**What replaces it:** A short post-exit "tool referenced paths" hint
plus a `dizgin add-path <path>` subcommand. The user sees the list, picks
the one they care about, and types one command — no decision tree.

**Future plan:** Interactive access prompt v2, opt-in flag (`dizgin
--prompt-on-exit`). Built on `gum` or `huh` (charmbracelet), async so
exit is not blocked, with a "remember this answer" affordance.

### `dizgin unstamp` / `dizgin audit-low` (removed 2026-05-18)

**Was:** `cmd/dizgin/incident_recovery_windows.go` (~270 LOC). Operator
remediation commands for the 2026-05-17 Low IL time-bomb incident.

**Why removed:** The 2026-05-17 Low IL drift incident was an
AppContainer-era artifact; iter6 retired AppContainer and iter7
removed `dizgind setup` (along with `--repair`) because the
restricted backend preserves NTFS bypass-traversal natively.

**What replaces it:** Nothing today. Post-incident recovery v2
(`dizgind heal`) is the planned successor — see below.

**Future plan:** Post-incident recovery v2 if a similar inheritance-
leak class of bug appears again. Until then the iter3 + iter4
defensive denylist in `internal/security/path_classify_windows.go`
keeps the regression risk low.

---

## Active R&D

### Hyper-V isolation tier (shimV2 / HCS v2)

The retired HCS v1 container path could be reactivated when Microsoft
ships shimV2 with the registry-state fix that broke runhcs in
2026-04-28. Tracking: Q3-Q4 2026 release window. R7 climbs from
`kernel-shared` back to `kernel-isolated` if/when this lands.

### Linux Landlock + seccomp-BPF profile harmonisation

The current bwrap backend mounts everything via namespace binds and a
hand-tuned seccomp profile. Landlock LSM (kernel 5.13+) offers a
cleaner R1-C surface — per-path read/exec rules without unshare. The
question is how much of the existing bwrap profile to keep vs migrate;
Landlock is additive, not a replacement.

### macOS Endpoint Security framework

Seatbelt (sandbox-exec) is deprecated but functional on every macOS we
ship to. Endpoint Security is the long-term replacement. R&D scope:
write a parallel ES-based backend, gate it behind capability detection,
ship both for a release before removing the Seatbelt path.

### Per-tool LLM-suggested profile snippets

Profiles in `~/.dizgin/profiles/` are hand-authored YAML. A future
`dizgin add-path --suggest` mode could ask an LLM to map the tool's
"tried to read X" output to the right `config_dirs` / `lib_deps` /
`tool_deps` bucket. Boundary case to watch: the LLM never gets to
write its suggestion straight to disk — the user always sees the
diff first.

---

## Won't do

These were considered and explicitly rejected.

### Docker integration

DIZGIN's contract is `host_path == guest_path` (R2 native experience).
Docker breaks that with bind mount remapping and PID/UID namespace
translation. A "Docker mode" would invert R2 entirely and add a
runtime requirement (Docker Desktop, Linux daemon) that the AI-coding-
tool audience doesn't have. Use Dev Containers if Docker is the
desired model.

### FUSE / overlay filesystem layering

R1's "declared paths only" invariant relies on the platform DACL /
SBPL / namespace doing the gating. Layering FUSE on top adds a
userspace component that the kernel must traverse on every syscall —
overhead measured at ~15-30 % in pilots, plus a single point of
failure that R1 specifically routes around.

### Path translation

Tools embed absolute paths in their state (~/.claude/config.json
references `/Users/x/...` or `C:\Users\X\...` literally). Translating
those at the sandbox boundary requires intercepting open()/readdir()
and rewriting every match. Every shipping attempt at this (WSL,
Docker Desktop, ms-sandbox) added a stream of "path translation
quirks" issues. DIZGIN's R2 says no.
