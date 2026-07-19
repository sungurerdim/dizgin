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
	"sort"
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
	if opts.Network == config.NetworkAllowlist {
		// Current macOS sandbox-exec rejects (remote ip/tcp "<addr>:<port>")
		// filters outright unless <addr> is literally "*" or "localhost" —
		// verified empirically on macOS 26.5.2 across both IPv4 ("host must
		// be * or localhost in network address") and IPv6 (the address's
		// own colons desync the parser into an internal assertion crash,
		// "Assertion failed (is_pair(p)), function car, file
		// sbpl_parser.c"). There is no SBPL syntax left that expresses a
		// per-host outbound allowlist on this OS, so every session under
		// this policy currently either crashes sandbox-exec or gets cleanly
		// rejected by it — the tool never starts, with no indication of
		// why. Fail closed here instead, before spending a session on a
		// profile that cannot work, with an error that says what actually
		// happened and what to do about it.
		return nil, fmt.Errorf("seatbelt: network.policy=allowlist is not supported on this macOS version — " +
			"sandbox-exec's SBPL no longer accepts an IP or hostname in a (remote ...) filter (only \"*\" or " +
			"\"localhost\"), so per-host network enforcement cannot be expressed. Use network.policy=open " +
			"(unrestricted egress) or network.policy=blocked (no egress) instead")
	}
	profile := generateProfile(opts, nil)
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

// developerDirSymlink is the fixed system symlink macOS itself maintains to
// record which Xcode/Command-Line-Tools install is "selected" — read by
// xcode-select(1) and, transitively, by any tool that shells out to it
// (git, python3, cc, make, swift, and most other Xcode-CLT-provided
// binaries all probe it during startup on a machine that has Xcode/CLT
// installed at all).
const developerDirSymlink = "/var/select/developer_dir"

// writeDeveloperDirAllow grants read access to wherever developerDirSymlink
// actually points on THIS machine — resolved at profile-generation time,
// never hardcoded, since the target varies (a full Xcode.app under
// /Applications for some developers, /Library/Developer/CommandLineTools
// for others, or the symlink may not exist at all on a machine with
// neither installed). The symlink itself carries zero sensitive content
// (it is pure system configuration, publicly readable by any process
// today), and the resolved target is a toolchain install, not user data.
//
// Skips silently when the symlink doesn't exist — that's the normal state
// on a machine with no Xcode/CLT installed, and tools that need it will
// simply report "not installed" the same way they would outside the
// sandbox.
func writeDeveloperDirAllow(sb *strings.Builder) {
	resolved, err := filepath.EvalSymlinks(developerDirSymlink)
	if err != nil {
		return
	}
	// /var is itself a symlink to /private/var (see writeBaseAllows), so
	// the kernel checks rules against /private/var/select/developer_dir,
	// not the /var/... spelling — both forms are needed, exactly as for
	// every other /var-rooted path in this profile. Substituting the
	// fixed "/var" -> "/private/var" prefix (rather than
	// filepath.EvalSymlinks on the whole path) keeps the developer_dir
	// component itself as a symlink reference instead of resolving it
	// too, which would collapse it to `resolved` and lose the distinct
	// rule this loop needs for the symlink node.
	privateVarForm := "/private" + developerDirSymlink
	for _, varForm := range []string{developerDirSymlink, privateVarForm} {
		fmt.Fprintf(sb, "(allow file-read-metadata (literal %s))\n", sbplQuotePath(filepath.Dir(varForm)))
		fmt.Fprintf(sb, "(allow file-read* (literal %s))\n", sbplQuotePath(varForm))
	}
	for _, a := range pathAncestors(resolved) {
		fmt.Fprintf(sb, "(allow file-read-metadata (literal %s))\n", sbplQuotePath(a))
	}
	fmt.Fprintf(sb, "(allow file-read* (subpath %s))\n", sbplQuotePath(resolved))
}

// writeUserTempDirAllow grants read+write access to the process's actual
// $TMPDIR — macOS's real per-user scratch directory (confstr
// _CS_DARWIN_USER_TEMP_DIR, e.g. /var/folders/xw/<hash>/T/), which is a
// COMPLETELY DIFFERENT location from the shared /tmp already covered in
// writeBaseAllows. Countless ordinary tools default to $TMPDIR rather than
// /tmp for scratch files — Python's tempfile module among them — so
// without this, any tool run from a workdir that doesn't happen to BE
// $TMPDIR gets silently denied the temp directory macOS itself told it to
// use. dizgin never overrides $TMPDIR on this backend (Seatbelt already
// isolates the filesystem), so the value is whatever the host environment
// set — resolved here at profile-generation time, not hardcoded, since it
// varies per user and per login session.
func writeUserTempDirAllow(sb *strings.Builder) {
	tmpdir := os.Getenv("TMPDIR")
	if tmpdir == "" {
		return
	}
	tmpdir = filepath.Clean(tmpdir)
	resolved := resolvedHost(tmpdir)
	for _, form := range []string{tmpdir, resolved} {
		for _, a := range pathAncestors(form) {
			fmt.Fprintf(sb, "(allow file-read-metadata (literal %s))\n", sbplQuotePath(a))
		}
	}
	fmt.Fprintf(sb, "(allow file-read* file-write* (subpath %s))\n", sbplQuotePath(resolved))
}

// generateProfile creates a Seatbelt SBPL profile from the given options.
// allowlistIPs are the pre-resolved IP literals for the network allowlist
// (nil unless opts.Network == NetworkAllowlist).
func generateProfile(opts sandbox.CreateOpts, allowlistIPs []string) string {
	var sb strings.Builder
	sb.WriteString("(version 1)\n")
	writeBaseAllows(&sb)
	writeDeveloperDirAllow(&sb)
	writeUserTempDirAllow(&sb)
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
	// /etc, like /tmp, is a symlink to /private/etc on every stock macOS
	// install — real tools (curl's DNS/resolver lookup path among them)
	// stat the /etc spelling directly, so both forms are needed.
	sb.WriteString("(allow file-read* (subpath \"/private/etc\"))\n")
	sb.WriteString("(allow file-read* (subpath \"/etc\"))\n")
	// /tmp is a symlink to /private/tmp on every stock macOS install and the
	// kernel matches (subpath ...) rules against its own resolved path, not
	// the rule's literal text — a bare "/tmp" rule silently matches nothing
	// once anything resolves through the symlink. Both forms are covered
	// via literal fixed strings (cheap, and /tmp -> /private/tmp is stable
	// macOS behavior, unlike an arbitrary user path which needs the runtime
	// resolvedHost() treatment below).
	sb.WriteString("(allow file-read* (subpath \"/tmp\"))\n")
	sb.WriteString("(allow file-write* (subpath \"/tmp\"))\n")
	sb.WriteString("(allow file-read* (subpath \"/private/tmp\"))\n")
	sb.WriteString("(allow file-write* (subpath \"/private/tmp\"))\n")
	// /var is the third stock top-level symlink to /private/var. Metadata
	// only (not a subpath data allow): real tools (curl's TLS/cert-store
	// path among them) stat "/var" itself during startup, but the broader
	// /var tree holds system state (/var/db, /var/root, /var/log) that
	// stays denied by default — this only confirms the node exists.
	sb.WriteString("(allow file-read-metadata (literal \"/var\"))\n")

	// System preference reads (CFPreferences) and the DTrace helper probe:
	// both routinely touched by ordinary CLI tools during startup (TLS
	// trust store lookups, standard library init) and neither carries the
	// credential-grade sensitivity of the R1 SSOT.
	sb.WriteString("(allow user-preference-read)\n")
	sb.WriteString("(allow file-read* (literal \"/dev/dtracehelper\"))\n")

	// Pseudo-devices every real tool needs (output suppression, randomness,
	// controlling terminal, fd-passthrough). Deliberately NOT a blanket
	// (subpath "/dev") allow — /dev also holds raw disk nodes (disk0,
	// disk0s1, ...) that would hand a sandboxed process direct block-device
	// access, bypassing every filesystem permission entirely. Verified
	// empirically that /dev was 100% denied by default (deny default) with
	// no rule at all: any `> /dev/null` redirect — which is nearly every
	// shell invocation — failed outright before this was added.
	sb.WriteString("(allow file-read* file-write* (literal \"/dev/null\"))\n")
	sb.WriteString("(allow file-read* (literal \"/dev/zero\"))\n")
	sb.WriteString("(allow file-read* (literal \"/dev/urandom\"))\n")
	sb.WriteString("(allow file-read* (literal \"/dev/random\"))\n")
	sb.WriteString("(allow file-read* file-write* (literal \"/dev/tty\"))\n")
	sb.WriteString("(allow file-read* file-write* (literal \"/dev/stdin\"))\n")
	sb.WriteString("(allow file-read* file-write* (literal \"/dev/stdout\"))\n")
	sb.WriteString("(allow file-read* file-write* (literal \"/dev/stderr\"))\n")
	sb.WriteString("(allow file-read* file-write* (subpath \"/dev/fd\"))\n")

	// The root directory itself needs both metadata AND data read, not just
	// traversal metadata like every other ancestor below: verified
	// empirically on macOS 26 that even a minimal `bash -c "echo hi"` with
	// no file access at all aborts (SIGABRT, kernel log: "deny file-read-data
	// /") without this — the shell's own startup touches "/" directly, not
	// merely walks through it.
	sb.WriteString("(allow file-read-metadata (literal \"/\"))\n")
	sb.WriteString("(allow file-read-data (literal \"/\"))\n")
}

// pathAncestors returns every proper ancestor directory of path, nearest
// first, excluding the root ("/" — already covered unconditionally by
// writeBaseAllows) and excluding path itself (covered by the caller's own
// subpath/literal allow rule).
func pathAncestors(path string) []string {
	clean := filepath.Clean(path)
	var out []string
	for {
		parent := filepath.Dir(clean)
		if parent == clean || parent == "/" || parent == "." {
			break
		}
		out = append(out, parent)
		clean = parent
	}
	return out
}

// resolvedHost returns the symlink-canonical form of path, falling back to
// path itself when EvalSymlinks fails (e.g. the directory doesn't exist
// yet). macOS Seatbelt matches (subpath ...) rules against the kernel's
// resolved path, not the rule's literal text. /tmp and /var are themselves
// symlinks to /private/tmp and /private/var on every stock macOS install,
// so any mount rooted under a mktemp(1) scratch dir (which lands under
// /var/folders/...) silently matches nothing unless canonicalized first —
// verified empirically on macOS 26: an un-resolved workdir mount denied
// every read/write inside its own tree, not merely ancestor traversal.
func resolvedHost(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}

// writeMountAllows emits one read (or read+write) rule per profile-declared
// mount, plus a metadata-only traversal allow for every ancestor directory
// of every mount. Without this, any process whose cwd (or an absolute path
// lookup) passes through an ancestor that carries no rule of its own gets
// an implicit deny: macOS Seatbelt checks read-metadata permission on each
// path component during lookup, even when the final target is already
// covered by a `(subpath ...)` allow. Metadata-only (not data) so this
// traversal grant never exposes directory *listings* of unrelated siblings
// (e.g. other accounts under /Users) — it only confirms the named
// component exists, which is what path resolution needs.
func writeMountAllows(sb *strings.Builder, mounts []sandbox.Mount) {
	resolvedMounts := make([]sandbox.Mount, len(mounts))
	ancestors := make(map[string]bool)
	for i, m := range mounts {
		resolvedMounts[i] = m
		resolvedMounts[i].Host = resolvedHost(m.Host)
		// Ancestors of BOTH the resolved (canonical) path AND the
		// original (as-declared) path are needed, not just the
		// resolved one: when an intermediate component of the
		// ORIGINAL path is itself a symlink (e.g. Homebrew's
		// convenience layout, /opt/homebrew/opt/<pkg> ->
		// ../Cellar/<pkg>/<version>), the kernel must read-metadata
		// that symlink itself before it can even discover where it
		// points — a rule that only covers the canonical destination's
		// ancestry never grants permission to follow the symlink in
		// the first place. Verified empirically: a dynamically
		// resolved dependency mount for Homebrew git's pcre2 dylib
		// (referenced by git as /opt/homebrew/opt/pcre2/lib/...) was
		// denied outright — SIGABRT — until /opt/homebrew/opt and
		// /opt/homebrew/opt/pcre2 also got metadata allows, even
		// though the canonical /opt/homebrew/Cellar/pcre2/... chain
		// was already fully covered.
		for _, a := range pathAncestors(resolvedMounts[i].Host) {
			ancestors[a] = true
		}
		for _, a := range pathAncestors(m.Host) {
			ancestors[a] = true
		}
	}
	sorted := make([]string, 0, len(ancestors))
	for a := range ancestors {
		sorted = append(sorted, a)
	}
	sort.Strings(sorted)
	for _, a := range sorted {
		fmt.Fprintf(sb, "(allow file-read-metadata (literal %s))\n", sbplQuotePath(a))
	}

	for _, m := range resolvedMounts {
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
	cfg         *config.Config
	opts        sandbox.CreateOpts
	profile     string
	profilePath string
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
	// Removed in Cleanup(), not here: Cmd.Start()/StartWithPTY() below only
	// guarantees fork+exec has happened, not that the newly-exec'd
	// sandbox-exec binary has reached the point in its own runtime where it
	// open()s the profile path. Deleting it immediately after Start()
	// returns races that read and lost 100% of the time in practice —
	// sandbox-exec found the file already gone and refused to run the
	// child at all (exit 65). The file must outlive the child process.
	b.profilePath = profilePath

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
//
// resources.memory_mb specifically: Darwin's kernel rejects
// setrlimit(RLIMIT_AS, <finite>) unconditionally — it only accepts
// RLIM_INFINITY, regardless of the requested value. This is a permanent
// XNU limitation (the same reason bash's `ulimit -v` reports "not
// supported" on macOS), not a fixable code bug, so memory_mb has no
// enforcement path on this backend today. The warning below says so
// explicitly rather than emitting a bare "invalid argument" syscall error
// that gives no indication the configured limit is silently not applied.
func applyResourceLimits(res config.ResourceConfig) {
	if res.MemoryMB <= 0 && res.MaxPIDs <= 0 {
		return
	}
	rlCfg := platform.RlimitConfig{
		MemoryMB: res.MemoryMB,
		MaxPIDs:  res.MaxPIDs,
	}
	if err := platform.ApplyRlimits(rlCfg); err != nil {
		fmt.Fprintf(os.Stderr, brand.Name+": resource limit not fully applied (%v). "+
			"Note: resources.memory_mb cannot be enforced on macOS — the kernel rejects "+
			"a finite RLIMIT_AS unconditionally; this session's memory is NOT capped.\n", err)
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
	// Safe to remove now: by the time Cleanup runs the child has either
	// exited (normal Start -> Wait -> Cleanup flow) or is being force-killed
	// above, so sandbox-exec is done reading the profile either way.
	// Idempotent (os.Remove on an already-removed path is a no-op error we
	// discard) — teardownSession and main.go's defer both call Cleanup.
	if b.profilePath != "" {
		os.Remove(b.profilePath) //nolint:errcheck
		b.profilePath = ""
	}
	return nil
}
