// SPDX-License-Identifier: MIT

//go:build darwin

// Package seatbelt implements the macOS Seatbelt sandbox backend using
// sandbox-exec(1) with a generated sandbox profile (SBPL).
package seatbelt

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/config"
	"github.com/sungurerdim/dizgin/internal/permissions"
	"github.com/sungurerdim/dizgin/internal/platform"
	"github.com/sungurerdim/dizgin/internal/sandbox"
	"github.com/sungurerdim/dizgin/internal/sandbox/posixbox"
	"github.com/sungurerdim/dizgin/internal/security"
)

const BackendName = "seatbelt"

func init() {
	sandbox.Register(&backend{})
}

type backend struct{}

func (b *backend) Name() string { return BackendName }
func (b *backend) Available() bool {
	_, err := exec.LookPath("sandbox-exec")
	return err == nil
}

func (b *backend) Create(ctx context.Context, cfg *config.Config, opts sandbox.CreateOpts) (sandbox.Box, error) {
	// Resolve the network allowlist to IP literals up front. SBPL filters
	// on IPs, not hostnames, so this must happen before the profile is
	// built. Fail-closed: an unresolvable host aborts session creation
	// rather than silently producing a profile that blocks it — a
	// half-open network policy is worse than a clear error.
	var allowlistIPs []string
	if opts.Network == config.NetworkAllowlist {
		ips, err := resolveAllowlistIPs(ctx, opts.Allowlist)
		if err != nil {
			return nil, err
		}
		allowlistIPs = ips
	}
	profile := generateProfile(opts, allowlistIPs)
	return &box{cfg: cfg, opts: opts, profile: profile}, nil
}

// LoadPermissionOverrides implements sandbox.PermissionProfileLoader so a
// user can authorise a sensitive path for a tool by editing
// ~/.dizgin/permissions/<tool>.yaml, exactly as on Windows. Returns
// (nil, nil) when no profile exists yet.
func (b *backend) LoadPermissionOverrides(toolName string) (*sandbox.PermissionOverrides, error) {
	return permissions.Load(toolName)
}

// sbplQuotePath wraps path in SBPL double-quote syntax, escaping only
// the characters that SBPL treats as special: double-quote and backslash.
func sbplQuotePath(path string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, c := range path {
		switch c {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		default:
			sb.WriteRune(c)
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

// dnsLookupTimeout bounds each per-host resolution in resolveAllowlistIPs so
// a slow or hung resolver cannot block session creation indefinitely.
const dnsLookupTimeout = 5 * time.Second

// resolveAllowlistIPs resolves every allowlisted host to its current A/AAAA
// records, deduplicated. Fail-closed: an empty allowlist, an entry that
// carries a CIDR mask (unsupported by SBPL's per-IP filter), or a host
// that fails to resolve returns an error so the caller can abort the
// session instead of shipping a policy that silently blocks the host.
func resolveAllowlistIPs(ctx context.Context, hosts []string) ([]string, error) {
	if len(hosts) == 0 {
		return nil, fmt.Errorf("seatbelt: network allowlist policy requires at least one host")
	}
	seen := make(map[string]bool)
	var out []string
	var resolver net.Resolver
	for _, h := range hosts {
		if strings.ContainsRune(h, '/') {
			return nil, fmt.Errorf("seatbelt: CIDR allowlist entry %q is not supported (SBPL filters per-IP); list explicit hosts instead", h)
		}
		lookupCtx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
		addrs, err := resolver.LookupIPAddr(lookupCtx, h)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("seatbelt: resolve allowlist host %q: %w (fix DNS/the host, or set network.policy to open/blocked)", h, err)
		}
		for _, addr := range addrs {
			s := addr.IP.String()
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out, nil
}

// generateProfile creates a Seatbelt SBPL profile from the given options.
// allowlistIPs are the pre-resolved IP literals for the network allowlist
// (nil unless opts.Network == NetworkAllowlist).
func generateProfile(opts sandbox.CreateOpts, allowlistIPs []string) string {
	var sb strings.Builder
	sb.WriteString("(version 1)\n")
	writeBaseAllows(&sb)
	writeMountAllows(&sb, opts.Mounts)

	// R1 — Sensitive Surface Isolation. Emitted AFTER the mount-allow loop
	// so SBPL's last-match-wins gives the deny priority over any broad
	// grant above (system dirs, /tmp, or a mount that happens to contain a
	// credential path). The user-authorised override allows are emitted
	// LAST (below) so an explicitly-granted path wins over this deny.
	writeSensitiveDeny(&sb, opts)

	writeNetworkRules(&sb, opts.Network, allowlistIPs)

	return sb.String()
}

// writeBaseAllows emits the fixed process/IPC/filesystem allow rules every
// session needs regardless of profile options.
func writeBaseAllows(sb *strings.Builder) {
	// Start with a base deny-all then selectively allow.
	sb.WriteString("(deny default)\n")
	sb.WriteString("(allow signal)\n")
	sb.WriteString("(allow process-exec)\n")
	// process-fork is intentionally allowed: AI coding tools regularly
	// spawn subprocesses (git, npm, language servers, build tooling).
	// Containment is enforced via the allowlist filesystem + network
	// rules below, which apply transitively to every fork descendant.
	sb.WriteString("(allow process-fork)\n")
	sb.WriteString("(allow sysctl-read)\n")
	sb.WriteString("(allow mach-lookup)\n")
	sb.WriteString("(allow ipc-posix-sem)\n")
	sb.WriteString("(allow ipc-posix-shm)\n")

	// Allow reading system libraries and frameworks.
	sb.WriteString("(allow file-read* (subpath \"/usr\"))\n")
	sb.WriteString("(allow file-read* (subpath \"/System\"))\n")
	sb.WriteString("(allow file-read* (subpath \"/Library\"))\n")
	sb.WriteString("(allow file-read* (subpath \"/private/etc\"))\n")
	sb.WriteString("(allow file-read* (subpath \"/tmp\"))\n")
	sb.WriteString("(allow file-write* (subpath \"/tmp\"))\n")
}

// writeMountAllows emits one read (or read+write) rule per profile-declared
// mount.
func writeMountAllows(sb *strings.Builder, mounts []sandbox.Mount) {
	for _, m := range mounts {
		if m.ReadOnly {
			fmt.Fprintf(sb, "(allow file-read* (subpath %s))\n", sbplQuotePath(m.Host))
		} else {
			fmt.Fprintf(sb, "(allow file-read* (subpath %s))\n", sbplQuotePath(m.Host))
			fmt.Fprintf(sb, "(allow file-write* (subpath %s))\n", sbplQuotePath(m.Host))
		}
	}
}

// writeNetworkRules emits the network policy block: full access (open),
// resolved-IP allowlist entries (allowlist — loopback+DNS always open), or
// nothing (blocked — network* stays denied by the base default-deny).
func writeNetworkRules(sb *strings.Builder, policy config.NetworkPolicy, allowlistIPs []string) {
	switch policy {
	case config.NetworkOpen:
		sb.WriteString("(allow network*)\n")
	case config.NetworkAllowlist:
		// SBPL's (remote tcp ...) filter matches on resolved IP literals,
		// NOT hostnames — a `"github.com:443"` rule silently matches
		// nothing. Resolve each allowlisted host to its current A/AAAA
		// records and emit one rule per IP. Loopback + DNS stay open so
		// the tool can still resolve names at runtime.
		sb.WriteString("(allow network* (local))\n")
		sb.WriteString("(allow network-outbound (remote ip \"localhost:*\"))\n")
		sb.WriteString("(allow network* (remote udp \"*:53\"))\n")
		sb.WriteString("(allow network* (remote tcp \"*:53\"))\n")
		for _, ip := range allowlistIPs {
			fmt.Fprintf(sb, "(allow network-outbound (remote ip %s))\n", sbplQuotePath(ip+":443"))
			fmt.Fprintf(sb, "(allow network-outbound (remote ip %s))\n", sbplQuotePath(ip+":80"))
		}
	case config.NetworkBlocked:
		// network* remains denied by the default-deny at the top.
	}
}

// writeSensitiveDeny appends the R1 credential-isolation rules to the
// profile: a deny for every sensitive SSOT path (plus any user-declared
// extra deny), followed by re-allow rules for the paths the user
// authorised on a prior --learn run. SBPL is last-match-wins, so:
//
//   - deny sensitive → wins over the earlier mount/system allow
//   - allow override → wins over the deny just emitted
//
// RW override → read+write re-allowed; RO override → read only (write
// stays denied). A sensitive path with no override stays fully denied.
func writeSensitiveDeny(sb *strings.Builder, opts sandbox.CreateOpts) {
	// The Seatbelt kernel evaluates rules against the symlink-resolved
	// (canonical) path, so a deny keyed on an un-resolved home would
	// silently miss when any component is a symlink (verified empirically
	// on macOS 26: a rule on /var/... never matches the resolved
	// /private/var/... path). Canonicalize the home root once so every
	// derived deny/allow rule below lines up with what the kernel checks.
	// Best-effort: EvalSymlinks fails on a nonexistent home, in which case
	// the raw value is the only thing we have and is used as-is.
	home := os.Getenv("HOME")
	if resolved, err := filepath.EvalSymlinks(home); err == nil {
		home = resolved
	}

	deny := security.SensitiveDenyPaths(home)
	if ov := opts.PermissionOverrides; ov != nil {
		deny = append(deny, ov.Deny...)
	}
	for _, p := range deny {
		writeDenyRule(sb, p)
	}

	// Re-allow user-authorised paths last so they override the deny above.
	if ov := opts.PermissionOverrides; ov != nil {
		for _, p := range ov.RW {
			fmt.Fprintf(sb, "(allow file-read* (subpath %s))\n", sbplQuotePath(p))
			fmt.Fprintf(sb, "(allow file-write* (subpath %s))\n", sbplQuotePath(p))
		}
		for _, p := range ov.RO {
			fmt.Fprintf(sb, "(allow file-read* (subpath %s))\n", sbplQuotePath(p))
		}
	}
}

// writeDenyRule emits a read+write deny for one path. Directories use
// (subpath ...) so the whole subtree is covered; single files use
// (literal ...). The file/dir split follows the SSOT convention: a final
// path component with a real extension (a dot after the first character)
// is a file, everything else — including leading-dot dotdirs like .ssh —
// is a directory.
func writeDenyRule(sb *strings.Builder, path string) {
	form := "subpath"
	if sbplPathIsFile(path) {
		form = "literal"
	}
	fmt.Fprintf(sb, "(deny file-read* file-write* (%s %s))\n", form, sbplQuotePath(path))
}

// sbplPathIsFile reports whether the final path component names a file
// (has an extension) rather than a directory. ".ssh"/".netrc" (leading
// dot only) are directories by convention; "config.json"/"hosts.yml" are
// files.
func sbplPathIsFile(path string) bool {
	base := path[strings.LastIndexByte(path, '/')+1:]
	dot := strings.LastIndexByte(base, '.')
	return dot > 0
}

// box implements sandbox.Box for macOS seatbelt. The exec.Cmd-based
// Wait/Signal/Pid/PTY quartet is inherited from the embedded Lifecycle,
// shared with the bubblewrap backend (AST-04); Start/Cleanup stay here
// because sandbox-exec's profile-file argv differs completely from bwrap's.
type box struct {
	posixbox.Lifecycle
	cfg     *config.Config
	opts    sandbox.CreateOpts
	profile string
}

func (b *box) Start(ctx context.Context, cmdPath string, args []string, env []string) error {
	b.Mu.Lock()
	defer b.Mu.Unlock()

	if b.Started {
		return fmt.Errorf("seatbelt: already started")
	}

	profilePath, err := writeProfileFile(b.profile)
	if err != nil {
		return err
	}
	// Remove profile file after process starts (no longer needed).
	defer os.Remove(profilePath) //nolint:errcheck

	applyResourceLimits(b.cfg.Resources)

	sandboxArgs := append([]string{"-f", profilePath, cmdPath}, args...)
	b.Cmd = exec.CommandContext(ctx, "sandbox-exec", sandboxArgs...)
	b.Cmd.Env = env
	if b.opts.Workdir != "" {
		b.Cmd.Dir = b.opts.Workdir
	}

	if err := b.startProcess(); err != nil {
		return err
	}

	b.Started = true
	return nil
}

// writeProfileFile writes profile to a fresh temp file and returns its path.
func writeProfileFile(profile string) (string, error) {
	pf, err := os.CreateTemp("", "dizgin-seatbelt-*.sb")
	if err != nil {
		return "", fmt.Errorf("seatbelt: write profile: %w", err)
	}
	path := pf.Name()
	if _, err := pf.WriteString(profile); err != nil {
		pf.Close()
		os.Remove(path)
		return "", err
	}
	pf.Close()
	return path, nil
}

// applyResourceLimits sets process rlimits best-effort: limits are set on
// the current process and inherited by the child via fork+exec. A failure
// is logged, never fatal — a missing rlimit is not worth aborting the
// session over.
func applyResourceLimits(res config.ResourceConfig) {
	if res.MemoryMB <= 0 && res.MaxPIDs <= 0 {
		return
	}
	rlCfg := platform.RlimitConfig{
		MemoryMB: res.MemoryMB,
		MaxPIDs:  res.MaxPIDs,
	}
	if err := platform.ApplyRlimits(rlCfg); err != nil {
		fmt.Fprintf(os.Stderr, brand.Name+": rlimit (non-fatal): %v\n", err)
	}
}

// startProcess launches b.Cmd, allocating a PTY when the session requested
// one.
func (b *box) startProcess() error {
	if b.opts.PTY {
		// Allocate a PTY: sandbox-exec inherits the PTY as its controlling terminal.
		sess, err := posixbox.StartWithPTY(b.Cmd)
		if err != nil {
			return fmt.Errorf("seatbelt: start with PTY: %w", err)
		}
		b.Session = sess
		return nil
	}
	b.Cmd.Stdin = os.Stdin
	b.Cmd.Stdout = os.Stdout
	b.Cmd.Stderr = os.Stderr
	if err := b.Cmd.Start(); err != nil {
		return fmt.Errorf("seatbelt: start: %w", err)
	}
	return nil
}

func (b *box) Cleanup() error {
	b.Mu.Lock()
	defer b.Mu.Unlock()
	if b.Cmd != nil && b.Cmd.Process != nil && b.Started && !b.Done {
		b.Cmd.Process.Signal(syscall.SIGKILL) //nolint:errcheck
	}
	if b.Session != nil {
		b.Session.Close()
	}
	return nil
}
