# dizgin — Technical Specification

## 1. System Architecture

### 1.1 Binary Topology

```
┌─────────────────────────────────────────────────────────────┐
│  Host System                                                │
│                                                             │
│  ┌──────────┐     Named Pipe / Unix Socket     ┌─────────┐ │
│  │   dizgin    │ ◄──────────────────────────────► │ dizgind │ │
│  │ (wrapper)│     JSON: register/heartbeat/     │ (daemon) │ │
│  └────┬─────┘     deregister/command           └────┬────┘ │
│       │                                              │      │
│  ┌────▼─────────────────────┐              ┌────────▼────┐ │
│  │  Sandbox Process         │              │ Session     │ │
│  │  ┌─────────────────────┐ │              │ Registry    │ │
│  │  │ AI Tool (claude,    │ │              │ ┌─────────┐ │ │
│  │  │ codex, aider, etc.) │ │              │ │Sessions │ │ │
│  │  └─────────────────────┘ │              │ │Creds    │ │ │
│  │  Backend: Restricted/     │              │ │Status   │ │ │
│  │  Seatbelt/bubblewrap     │              │ └─────────┘ │ │
│  └──────────────────────────┘              └─────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 Module Structure

```
github.com/sungurerdim/dizgin/
├── cmd/
│   ├── dizgin/main.go              # Sandbox wrapper entry
│   └── dizgind/main.go         # Orchestration daemon entry
├── internal/
│   ├── sandbox/
│   │   ├── interface.go         # Backend + Box interfaces
│   │   ├── registry.go          # Register() + Get()
│   │   ├── restricted/          # Windows restricted token + Medium IL + Job Object
│   │   ├── seatbelt/            # macOS Seatbelt
│   │   └── bubblewrap/          # Linux bubblewrap
│   ├── daemon/
│   │   ├── server.go            # IPC server (pipe/socket)
│   │   ├── client.go            # IPC client (dizgin side)
│   │   └── instance.go          # Instance registry
│   ├── config/
│   │   ├── config.go            # Config struct
│   │   ├── loader.go            # YAML load + validation
│   │   └── tools.go             # Tool mount maps
│   ├── credential/
│   │   ├── discover.go          # Host credential scan
│   │   ├── ssh.go               # SSH agent forwarding
│   │   ├── apikey.go            # API key env injection
│   │   ├── github.go            # GitHub token resolution
│   │   └── git.go               # Git identity detection
│   └── platform/
│       ├── detect.go            # OS detection
│       └── suspend.go           # Suspend/resume per OS
└── go.mod
```

### 1.3 Sandbox Interface

```go
type Backend interface {
    Name() string
    Available() bool
    Create(cfg *config.Config, opts CreateOpts) (Box, error)
}

type Box interface {
    Start(cmd string, args []string, env []string) error
    Wait() (int, error)
    Signal(sig os.Signal) error
    PTY() io.ReadWriteCloser
    Cleanup() error
}

type CreateOpts struct {
    Workdir     string
    Mounts      []Mount
    Credentials []Credential
    Network     NetworkPolicy
    Resources   ResourceLimits
}
```

### 1.4 Registry Pattern

```go
var backends = make(map[string]Backend)

func Register(b Backend) { backends[b.Name()] = b }

func Get() (Backend, error) {
    for _, b := range backends {
        if b.Available() { return b, nil }
    }
    return nil, errors.New("no sandbox backend available")
}
```

## 2. Data Model

### 2.1 Config Schema

```yaml
security:
  filesystem:
    project_rw: true
    system_readonly: true
    tmpfs_tmp: true
    zero_residue: false
  network:
    policy: open  # open | allowlist | blocked
    allowlist: ["api.anthropic.com", "api.openai.com", "registry.npmjs.org", "github.com"]
  resources:
    memory: "4GB"
    cpu: 2.0
    pids: 2048
  privileges:
    no_new_privileges: true
    drop_all_caps: true

credentials:
  auto_discover: true
  active:
    ssh_agent: true
    anthropic_api_key: true
    github_token: true
    git_identity: true

tools:
  claude:
    config_dirs: ["~/.claude"]
    env_keys: ["ANTHROPIC_API_KEY"]
  codex:
    config_dirs: ["~/.codex"]
    env_keys: ["OPENAI_API_KEY"]
  aider:
    config_dirs: ["~/.aider.conf.yml", "~/.aider.models.yml"]
    env_keys: ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]
  gemini:
    config_dirs: ["~/.gemini"]
    env_keys: ["GEMINI_API_KEY"]
  opencode:
    config_dirs: ["~/.config/opencode"]
    env_keys: ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]
```

### 2.2 IPC Protocol

```jsonc
// register
{"type": "register", "id": "uuid", "pid": 1234, "tool": "claude", "workdir": "/path", "backend": "restricted"}
// heartbeat
{"type": "heartbeat", "id": "uuid", "status": "running", "last_prompt_snippet": "Implement the auth..."}
// deregister
{"type": "deregister", "id": "uuid", "exit_code": 0}
// command
{"type": "command", "id": "uuid", "action": "suspend"}
```

## 3. API Design

### 3.1 dizgin CLI

```
dizgin [-w <workdir>] [ENV=val...] <tool> [tool-args...]
```

### 3.2 dizgind CLI

```
dizgind start        # Start daemon
dizgind stop         # Stop daemon
dizgind status       # JSON instance list
dizgind heal         # Windows: DACL drift scan (--apply to revoke); no-op elsewhere
dizgind completion   # Shell completion
```

## 4. Security Model

### 4.0 Windows restricted-token backend: DACL DENY semantics

The Windows backend (iter6+) does not bind-mount. Filesystem isolation comes from a DENY-list model: a small set of 19 sensitive credential surfaces receive DENY ACEs via `SetNamedSecurityInfo`; everything else is governed by the user's natural NTFS rights. The restricted process runs as the same user as dizgin (same SID), so any path the user can normally access is also accessible to the sandboxed tool — except for the DENY-listed paths.

**DENY-stamp pipeline:**

| Step | Actor | Effect |
|------|-------|--------|
| 1 | dizgin process | `restricted.Backend.Create` calls `buildSensitiveDenyJobs` to enumerate the 19 SSOT paths from `internal/security/sensitive_paths_windows.go` |
| 2 | dizgin process | `StampPathDeny(host)` calls `SetNamedSecurityInfo` with a `DENY` ACE (`GENERIC_ALL` + `OI`+`CI` inheritance) on each existing sensitive path — non-existent paths are silently skipped |
| 3 | dizgin process | On any stamp failure, dizgin aborts session creation and rolls back all applied DENY ACEs — partial state is never left behind |
| 4 | dizgin process | `restricted.Box.Start` builds a `STARTUPINFOEX`, creates the process under a `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` token at **Medium IL** (`S-1-16-8192`), and assigns it to a Job Object with `KILL_ON_JOB_CLOSE` + memory + PID + UI restrictions |
| 5 | dizgin process | `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` is set: DEP ON, ASLR force-relocate + high-entropy ON, ImageLoad restrictions ON, StrictHandleChecks ON, ACG **OFF** (Bun JIT compat) |
| 6 | tool | Reads / writes host paths directly (`host_path == guest_path`). Attempts to open a DENY-listed path return `ERROR_ACCESS_DENIED` |
| 7 | dizgin process (post-exit) | `Box.Cleanup` revokes the DENY ACEs via a tree-walk using `SET_ACCESS` (zero perms) — this strips both DENY and any GRANT ACEs, working around the documented `SetEntriesInAcl REVOKE_ACCESS` asymmetry |

**R1 result:** `host_path == guest_path` throughout. The 19 SSOT sensitive surfaces are blocked by DENY ACEs; the user's natural NTFS permissions cover all other paths. A path not on the DENY list and not restricted by the user's own ACL is readable and writable by the sandboxed tool.

### 4.1 Platform-Native Isolation

| Mechanism | Windows | macOS | Linux |
|-----------|---------|-------|-------|
| Process | Restricted token (Medium IL) + Job Object | Seatbelt profile | User namespace |
| Filesystem | DACL DENY ACEs on 19 sensitive SSOT paths (`host_path == guest_path`) | Seatbelt rules | bind mount (ro/rw) |
| Network | User-mode WFP allowlist (brokered by elevated dizgind daemon) | network-outbound | seccomp + netns |
| Resources | Job Object limits (memory, PID, UI) | rlimit | cgroups v2 |
| Privileges | Restricted token (DISABLE_MAX_PRIVILEGE) + Medium IL + UI restrictions | Sandbox profile | seccomp-BPF |

### 4.2 Credential Passthrough

| Credential | Method | Security |
|------------|--------|----------|
| SSH key | Agent socket forwarding | Key never enters sandbox |
| API key | 0600 temp → env var | Session-scoped |
| GitHub token | env → gh → git helper | Multi-source resolution |
| Git identity | user.name/email inject | Read-only |

### 4.3 Threat Model

| Threat | Level | Mitigation |
|--------|-------|------------|
| Destructive commands | PRIMARY | Filesystem isolation |
| Credential leak | HIGH | Agent forwarding, 0600 temp |
| Supply chain attack | HIGH | Network allowlist |
| MCP injection | MEDIUM | Sandbox MCP restriction |

### 4.4 IPC Security

| OS | Mechanism |
|----|-----------|
| Windows | Named pipe + DACL (current user only) |
| macOS/Linux | Unix socket 0600 + SO_PEERCRED |

## 5. Dependencies

| Package | Role | Risk |
|---------|------|------|
| manual ConPTY syscalls (x/sys/windows) | Windows PTY | Medium |
| creack/pty | Unix PTY | Low |
| spf13/viper | Config | Low |
| spf13/cobra | CLI | Low |
| golang.org/x/sys/windows | Win32 | Low |
