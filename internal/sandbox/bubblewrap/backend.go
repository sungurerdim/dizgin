// SPDX-License-Identifier: MIT

//go:build linux

// Package bubblewrap implements the Linux sandbox backend using bwrap(1)
// (Bubblewrap), which provides user-namespace-based sandboxing.
package bubblewrap

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/config"
	"github.com/sungurerdim/dizgin/internal/permissions"
	"github.com/sungurerdim/dizgin/internal/platform"
	"github.com/sungurerdim/dizgin/internal/sandbox"
	"github.com/sungurerdim/dizgin/internal/sandbox/posixbox"
	"github.com/sungurerdim/dizgin/internal/security"
)

const BackendName = "bubblewrap"

func init() {
	sandbox.Register(&backend{})
}

type backend struct{}

func (b *backend) Name() string { return BackendName }
func (b *backend) Available() bool {
	_, err := exec.LookPath("bwrap")
	return err == nil
}

func (b *backend) Create(_ context.Context, cfg *config.Config, opts sandbox.CreateOpts) (sandbox.Box, error) {
	// Linux filtered allowlist is not yet enforced. A bwrap --unshare-net
	// namespace has only loopback, so nft rules inside it cannot reach an
	// allowed host regardless — real per-host egress needs a veth+NAT pair
	// or a userland proxy (pasta/slirp4netns), which is root-requiring work
	// tracked in ROADMAP. Rather than silently downgrade to blocked (which
	// would also block the allowed hosts) or pretend to filter, fail closed
	// with a clear pointer. This matches the backend's no-silent-fallback
	// rule.
	if opts.Network == config.NetworkAllowlist {
		return nil, fmt.Errorf("bubblewrap: network.policy=allowlist is not yet enforced on Linux " +
			"(filtered egress needs a veth/NAT or userland-proxy layer — see ROADMAP); " +
			"use network.policy=blocked for no egress or open for full egress")
	}
	return &box{cfg: cfg, opts: opts}, nil
}

// LoadPermissionOverrides implements sandbox.PermissionProfileLoader so a
// user can authorise a sensitive path for a tool by editing
// ~/.dizgin/permissions/<tool>.yaml, exactly as on Windows. Returns
// (nil, nil) when no profile exists yet.
func (b *backend) LoadPermissionOverrides(toolName string) (*sandbox.PermissionOverrides, error) {
	return permissions.Load(toolName)
}

// box implements sandbox.Box using bwrap. The exec.Cmd-based
// Wait/Signal/Pid/PTY quartet is inherited from the embedded Lifecycle,
// shared with the seatbelt backend (AST-04); Start/Cleanup stay here
// because bwrap's mount/cover-file argv differs completely from
// sandbox-exec's profile file.
type box struct {
	posixbox.Lifecycle
	cfg  *config.Config
	opts sandbox.CreateOpts
	// coverFile is the empty 0000 file used to shadow sensitive files;
	// created lazily by ensureCoverFile, removed in Cleanup.
	coverFile string
}

func (b *box) Start(ctx context.Context, cmdPath string, args []string, env []string) error {
	b.Mu.Lock()
	defer b.Mu.Unlock()

	applyResourceLimits(b.cfg.Resources)

	bwrapArgs, seccompFile, err := b.buildCommandArgs(cmdPath, args)
	if err != nil {
		return err
	}

	b.Cmd = exec.CommandContext(ctx, "bwrap", bwrapArgs...)
	b.Cmd.Env = env
	if b.opts.Workdir != "" {
		b.Cmd.Dir = b.opts.Workdir
	}
	if seccompFile != nil {
		// Pass the seccomp fd as fd 3 in the child.
		b.Cmd.ExtraFiles = []*os.File{seccompFile}
		defer func() {
			seccompFile.Close()           //nolint:errcheck
			os.Remove(seccompFile.Name()) //nolint:errcheck
		}()
	}

	if err := b.startProcess(); err != nil {
		return err
	}
	b.Started = true
	return nil
}

// applyResourceLimits sets process rlimits best-effort: limits are set on
// the current process and inherited by the bwrap child via fork+exec. A
// failure is logged, never fatal — a missing rlimit is not worth aborting
// the session over.
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

// buildCommandArgs constructs the bwrap argument list and, when the
// seccomp filter is available, the file it must be passed on as fd 3
// (ExtraFiles[0] becomes fd 3 in the child, after stdin/stdout/stderr =
// 0/1/2). Seccomp unavailability is non-fatal — the returned file is nil
// and the caller runs without the extra filter.
func (b *box) buildCommandArgs(cmdPath string, cmdArgs []string) ([]string, *os.File, error) {
	bwrapArgs, err := b.buildBwrapArgs(cmdPath, cmdArgs)
	if err != nil {
		return nil, nil, err
	}
	f, err := seccompFilterFD()
	if err != nil {
		fmt.Fprintf(os.Stderr, brand.Name+": seccomp unavailable (non-fatal): %v\n", err)
		return bwrapArgs, nil, nil
	}
	// Insert --seccomp 3 before the "--" separator.
	bwrapArgs = insertBeforeSep(bwrapArgs, []string{"--seccomp", "3"})
	return bwrapArgs, f, nil
}

// startProcess launches b.Cmd, allocating a PTY when the session requested
// one.
func (b *box) startProcess() error {
	if b.opts.PTY {
		sess, err := posixbox.StartWithPTY(b.Cmd)
		if err != nil {
			return fmt.Errorf("bubblewrap: start with PTY: %w", err)
		}
		b.Session = sess
		return nil
	}
	b.Cmd.Stdin = os.Stdin
	b.Cmd.Stdout = os.Stdout
	b.Cmd.Stderr = os.Stderr
	if err := b.Cmd.Start(); err != nil {
		return fmt.Errorf("bubblewrap: start: %w", err)
	}
	return nil
}

// insertBeforeSep inserts extra args before the "--" separator in args.
// If no separator is found, extra args are appended at the end.
func insertBeforeSep(args []string, extra []string) []string {
	for i, a := range args {
		if a == "--" {
			result := make([]string, 0, len(args)+len(extra))
			result = append(result, args[:i]...)
			result = append(result, extra...)
			result = append(result, args[i:]...)
			return result
		}
	}
	return append(args, extra...)
}

// buildBwrapArgs constructs the bwrap argument list. Returns an error only
// when a required R1 cover cannot be prepared (fail-closed: a half-covered
// credential surface is worse than refusing the session).
func (b *box) buildBwrapArgs(cmdPath string, cmdArgs []string) ([]string, error) {
	var args []string
	args = appendSystemBinds(args)
	args = appendMountBinds(args, b.opts.Mounts)

	// R1 — Sensitive Surface Isolation. On Linux the home is not bound by
	// default, so a credential path is only reachable inside the sandbox
	// when it falls under one of the requested mounts above (e.g. the user
	// mounts $HOME, or workdir == $HOME). For each such path, shadow it:
	// a directory gets an empty 0000 tmpfs, a file gets a 0000 empty file
	// bound over it. Shadowing protects the real content regardless of the
	// in-namespace uid; the 0000 perms turn a read attempt into EACCES,
	// which the --learn recorder can surface. Emitted AFTER the mount loop
	// so the shadow wins over the bind it sits inside.
	coverArgs, err := b.sensitiveCoverArgs()
	if err != nil {
		return nil, err
	}
	args = append(args, coverArgs...)

	args = appendNamespaceFlags(args, b.opts.Network)

	// Working directory.
	if b.opts.Workdir != "" {
		args = append(args, "--chdir", b.opts.Workdir)
	}

	// Tool command.
	args = append(args, "--")
	args = append(args, cmdPath)
	args = append(args, cmdArgs...)

	return args, nil
}

// bwrapSystemPaths are the read-only host paths every session needs for a
// functioning userland (dynamic linker, shells, TLS trust store, DNS/passwd
// resolution).
var bwrapSystemPaths = []string{"/usr", "/lib", "/lib64", "/bin", "/sbin",
	"/etc/ssl", "/etc/resolv.conf", "/etc/passwd", "/etc/group"}

// appendSystemBinds appends read-only binds for the paths in
// bwrapSystemPaths that exist on this host, plus the tmpfs/proc/dev mounts
// every session needs.
func appendSystemBinds(args []string) []string {
	for _, p := range bwrapSystemPaths {
		if _, err := os.Stat(p); err == nil {
			args = append(args, "--ro-bind", p, p)
		}
	}
	args = append(args, "--tmpfs", "/tmp")
	args = append(args, "--proc", "/proc")
	args = append(args, "--dev", "/dev")
	return args
}

// appendMountBinds appends one --ro-bind or --bind per profile-declared
// mount whose host path exists; non-existent hosts are skipped.
func appendMountBinds(args []string, mounts []sandbox.Mount) []string {
	for _, m := range mounts {
		if _, err := os.Stat(m.Host); err != nil {
			continue // skip non-existent
		}
		if m.ReadOnly {
			args = append(args, "--ro-bind", m.Host, m.Guest)
		} else {
			args = append(args, "--bind", m.Host, m.Guest)
		}
	}
	return args
}

// appendNamespaceFlags appends the network-namespace choice plus the
// remaining namespace-isolation and hardening flags. Allowlist is rejected
// at Create() until filtered egress is implemented, so only blocked
// (isolated netns) and open (shared host net) reach here.
func appendNamespaceFlags(args []string, policy config.NetworkPolicy) []string {
	switch policy {
	case config.NetworkBlocked:
		args = append(args, "--unshare-net")
	default: // NetworkOpen
		args = append(args, "--share-net")
	}

	// Unshare other namespaces for isolation.
	args = append(args, "--unshare-user")
	args = append(args, "--unshare-ipc")
	args = append(args, "--unshare-pid")
	args = append(args, "--unshare-uts")

	// --die-with-parent: kill sandbox when the parent process exits.
	// --new-session: prevent the sandboxed process from controlling the
	// caller's terminal (setsid(2)), closing a tty-escape vector.
	args = append(args, "--die-with-parent")
	args = append(args, "--new-session")
	return args
}

// sensitiveCoverArgs emits the bwrap flags that shadow every reachable
// sensitive path (see the R1 comment in buildBwrapArgs). Directories are
// shadowed with an empty 0000 tmpfs; files are shadowed with a 0000 empty
// file bound read-only over them. Fail-closed: if a file cover is needed
// but the backing empty file cannot be created, an error is returned so the
// session refuses to start rather than exposing the credential.
func (b *box) sensitiveCoverArgs() ([]string, error) {
	home := os.Getenv("HOME")
	cands := coverCandidates(security.SensitiveDenyPaths(home), b.opts.Mounts, b.opts.PermissionOverrides)
	if len(cands) == 0 {
		return nil, nil
	}

	var args []string
	for _, p := range cands {
		fi, err := os.Stat(p)
		if err != nil {
			// Not present on the host (or unreadable to stat) — there is
			// nothing to shadow, and bwrap would fail to mount over a
			// missing target. Skip it.
			continue
		}
		if fi.IsDir() {
			// --perms sets the mode of the tmpfs mountpoint (bwrap ≥ 0.5.0,
			// released 2019 — universally available). The empty tmpfs
			// shadows the real directory regardless; 0000 turns a read into
			// EACCES so the --learn recorder sees a signal.
			args = append(args, "--perms", "0000", "--tmpfs", p)
			continue
		}
		cover, err := b.ensureCoverFile()
		if err != nil {
			return nil, fmt.Errorf("bubblewrap: cannot prepare R1 cover for %q: %w", p, err)
		}
		args = append(args, "--ro-bind", cover, p)
	}
	return args, nil
}

// ensureCoverFile lazily creates a single empty 0000-mode file used to
// shadow every sensitive *file* in the session, and caches its path on the
// box. Cleanup removes it. The file's content is empty and its mode is 0000
// so an in-sandbox read returns EACCES (a signal for --learn) while the
// real credential file stays hidden behind the bind.
func (b *box) ensureCoverFile() (string, error) {
	if b.coverFile != "" {
		return b.coverFile, nil
	}
	dir, err := os.MkdirTemp("", brand.Name+"-cover-*")
	if err != nil {
		return "", err
	}
	f := filepath.Join(dir, "empty")
	if err := os.WriteFile(f, nil, 0o000); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	b.coverFile = f
	return f, nil
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
	if b.coverFile != "" {
		_ = os.RemoveAll(filepath.Dir(b.coverFile))
		b.coverFile = ""
	}
	return nil
}
