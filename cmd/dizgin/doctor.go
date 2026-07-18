// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/config"
)

// doctorCheck reports the result of one preflight probe.
//
//	Pass  — check ran successfully and the system is healthy.
//	Fail  — check ran and detected a real problem.
//	Skip  — check did not run (not applicable on this platform / OS).
type doctorStatus string

const (
	doctorPass doctorStatus = "pass"
	doctorFail doctorStatus = "fail"
	doctorSkip doctorStatus = "skip"
)

type doctorCheck struct {
	Name    string       `json:"name"`
	Status  doctorStatus `json:"status"`
	Summary string       `json:"summary"`
	Hint    string       `json:"hint,omitempty"`
}

// runDoctor executes the full check suite and writes a report. Returns
// a non-nil error if any check failed (so dizgin doctor exits non-zero
// for shell pipelines and CI). The two output paths share a single
// check list — only the renderer differs.
func runDoctor(args []string) error {
	jsonOut := false
	for _, a := range args {
		switch a {
		case "--json":
			jsonOut = true
		case "-h", "--help":
			doctorUsage()
			return nil
		default:
			return fmt.Errorf("doctor: unknown flag %q", a)
		}
	}

	checks := collectDoctorChecks()

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(checks)
	} else {
		renderDoctorHuman(os.Stdout, checks)
	}

	for _, c := range checks {
		if c.Status == doctorFail {
			return fmt.Errorf("doctor: %d check(s) failed", countFails(checks))
		}
	}
	return nil
}

func countFails(checks []doctorCheck) int {
	n := 0
	for _, c := range checks {
		if c.Status == doctorFail {
			n++
		}
	}
	return n
}

func renderDoctorHuman(w io.Writer, checks []doctorCheck) {
	for _, c := range checks {
		var marker string
		switch c.Status {
		case doctorPass:
			marker = "[ OK ]"
		case doctorFail:
			marker = "[FAIL]"
		case doctorSkip:
			marker = "[SKIP]"
		default:
			marker = "[?]"
		}
		_, _ = fmt.Fprintf(w, "%s %s — %s\n", marker, c.Name, c.Summary)
		if c.Hint != "" {
			_, _ = fmt.Fprintf(w, "       hint: %s\n", c.Hint)
		}
	}
	fails := countFails(checks)
	if fails == 0 {
		_, _ = fmt.Fprintln(w, "\n"+brand.Name+" doctor: all checks passed.")
	} else {
		_, _ = fmt.Fprintf(w, "\n"+brand.Name+" doctor: %d check(s) failed.\n", fails)
	}
}

// collectDoctorChecks runs every registered check and returns the
// aggregate. Order matters: cheap config checks first, then runtime
// probes that may take a few hundred ms (daemon ping, AC smoke).
func collectDoctorChecks() []doctorCheck {
	out := []doctorCheck{
		checkConfigLoad(),
		checkDizginDirs(),
		checkProfilesLoad(),
		checkDaemonReachable(),
		checkDiskSpace(),
		checkScratchWritable(),
	}
	out = append(out, platformDoctorChecks()...)
	return out
}

// checkDizginDirs verifies the ~/.dizgin tree exists and is writable, and
// auto-fixes a missing tree by creating it (same philosophy as
// `dizgind heal`: doctor repairs what it safely can). Only a genuinely
// unwritable home surfaces as a failure the user must resolve.
func checkDizginDirs() doctorCheck {
	c := doctorCheck{Name: "dizgin dirs"}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		c.Status = doctorFail
		c.Summary = "cannot resolve user home directory"
		c.Hint = "set HOME (Unix) or USERPROFILE (Windows) to a writable directory"
		return c
	}
	base := filepath.Join(home, brand.DotDir)
	var created []string
	for _, sub := range brand.StateSubdirs {
		p := filepath.Join(base, sub)
		if _, statErr := os.Stat(p); os.IsNotExist(statErr) {
			if mkErr := os.MkdirAll(p, 0o755); mkErr != nil {
				c.Status = doctorFail
				c.Summary = fmt.Sprintf("could not create %s: %v", p, mkErr)
				c.Hint = "check that your home directory is writable"
				return c
			}
			created = append(created, sub)
		}
	}
	c.Status = doctorPass
	if len(created) > 0 {
		c.Summary = fmt.Sprintf("created missing dirs under %s: %s", base, strings.Join(created, ", "))
	} else {
		c.Summary = fmt.Sprintf("%s present (profiles, permissions, audit)", base)
	}
	return c
}

// checkScratchWritable confirms dizgin can actually create + remove a file
// in the scratch root the sandbox backends use. A read-only or
// permission-blocked scratch root produces cryptic mid-session failures,
// so probing it here turns a runtime crash into an actionable preflight.
func checkScratchWritable() doctorCheck {
	c := doctorCheck{Name: "scratch writable"}
	root := scratchRootForDoctor()
	probe := filepath.Join(root, ".dizgin-doctor-probe")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		c.Status = doctorFail
		c.Summary = fmt.Sprintf("cannot write to scratch root %s: %v", root, err)
		c.Hint = "ensure the scratch root is writable (Windows: %ProgramData%\\dizgin; Unix: ~/.dizgin) or free disk space"
		return c
	}
	_ = os.Remove(probe)
	c.Status = doctorPass
	c.Summary = fmt.Sprintf("scratch root %s is writable", root)
	return c
}

// checkConfigLoad attempts a Load with the configured config path and
// reports any parse / validation error. Empty configFile means "use
// defaults only" and is always a pass.
func checkConfigLoad() doctorCheck {
	c := doctorCheck{Name: "config load"}
	cfg, err := config.Load(configFile)
	if err != nil {
		c.Status = doctorFail
		c.Summary = err.Error()
		c.Hint = "edit your dizgin.yaml to fix the validation error, or unset -c to fall back to defaults"
		return c
	}
	c.Status = doctorPass
	if configFile == "" {
		c.Summary = "no config file specified; defaults loaded"
	} else {
		c.Summary = fmt.Sprintf("config loaded from %s (version %d)", configFile, cfg.Version)
	}
	return c
}

// checkProfilesLoad reloads the profile registry through the strict
// loader and counts how many tools resolved. Validation errors hit
// stderr inside the loader; this check just confirms nothing aborted
// the run and at least one profile survived.
func checkProfilesLoad() doctorCheck {
	c := doctorCheck{Name: "profiles load"}
	config.LoadProfiles(profilesDir)
	names := config.KnownToolNames()
	if len(names) == 0 {
		c.Status = doctorFail
		c.Summary = "no profiles registered (embedded + ~/.dizgin/profiles/ both empty?)"
		c.Hint = "profile parse errors print to stderr on every run; check them, or just run a tool — dizgin auto-detects an installed binary and writes a starter profile"
		return c
	}
	c.Status = doctorPass
	c.Summary = fmt.Sprintf("%d tool profile(s) loaded", len(names))
	return c
}

// checkDaemonReachable attempts a short ping to the dizgind daemon.
// We treat absence as a fail (dizgin's mainline path expects the daemon)
// but classify the failure with a clear remediation hint.
//
// Implementation notes: we only check whether the IPC endpoint is
// addressable, not whether it responds correctly — a deeper liveness
// probe risks wedging dizgin doctor when the daemon is half-up.
func checkDaemonReachable() doctorCheck {
	c := doctorCheck{Name: "daemon reachable"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := pingDaemon(ctx); err != nil {
		c.Status = doctorFail
		c.Summary = err.Error()
		c.Hint = "start the dizgind daemon (it autostarts on first dizgin call) or run: dizgind start"
		return c
	}
	c.Status = doctorPass
	c.Summary = "dizgind daemon responsive"
	return c
}

// checkDiskSpace ensures the cache + scratch roots have at least 256
// MiB free. Tight space here causes cryptic errors during stamp +
// scratch dir creation, so a green marker now saves debugging later.
func checkDiskSpace() doctorCheck {
	c := doctorCheck{Name: "disk space"}
	root := scratchRootForDoctor()
	free, err := freeBytesAt(root)
	if err != nil {
		c.Status = doctorSkip
		c.Summary = fmt.Sprintf("could not query disk space at %s: %v", root, err)
		return c
	}
	const minBytes = 256 * 1024 * 1024
	if free < minBytes {
		c.Status = doctorFail
		c.Summary = fmt.Sprintf("only %d MiB free at %s (want >= 256 MiB)", free/1024/1024, root)
		c.Hint = "free disk space, then re-run dizgin doctor"
		return c
	}
	c.Status = doctorPass
	c.Summary = fmt.Sprintf("%d MiB free at %s", free/1024/1024, root)
	return c
}

// scratchRootForDoctor mirrors the per-platform scratch tree the
// sandbox backends use. We pick the first writable candidate so this
// check stays in sync with where actual sessions write.
func scratchRootForDoctor() string {
	candidates := []string{}
	if pd := os.Getenv("ProgramData"); pd != "" {
		candidates = append(candidates, filepath.Join(pd, brand.Name))
	}
	if lad := os.Getenv("LOCALAPPDATA"); lad != "" {
		candidates = append(candidates, filepath.Join(lad, brand.Name))
	}
	if home, _ := os.UserHomeDir(); home != "" {
		candidates = append(candidates, filepath.Join(home, brand.DotDir))
	}
	candidates = append(candidates, os.TempDir())
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if fi, err := os.Stat(c); err == nil && fi.IsDir() {
			return c
		}
	}
	return os.TempDir()
}

func doctorUsage() {
	fmt.Fprint(os.Stderr, strings.TrimLeft(`
dizgin doctor [--json]

Run preflight health checks. Exit code 0 means all checks passed; any
failure produces a non-zero exit and a remediation hint per failed
check.

Flags:
  --json    Emit machine-readable JSON instead of the human report.

Checks:
  - config load          : dizgin.yaml parses + validates
  - dizgin dirs            : ~/.dizgin tree exists + writable (auto-creates if missing)
  - profiles load        : at least one tool profile registers
  - daemon reachable     : dizgind IPC endpoint responds
  - disk space           : >= 256 MiB free at scratch root
  - scratch writable     : scratch root accepts a probe write
`, "\n"))
}
