// SPDX-License-Identifier: MIT

// Package log provides simple leveled logging helpers for dizgin.
//
// All output goes to stderr with the brand.Name+": " prefix.
// Log levels: Error (always), Warn (unless DIZGIN_QUIET=1),
// Info (unless DIZGIN_QUIET=1), Debug (only when DIZGIN_DEBUG=1).
//
// Subsystem debug: DIZGIN_DEBUG=1 enables all debug output.
// DIZGIN_DEBUG=container,mount enables only those subsystems via DebugSub.
//
// Verbose framework master switch:
//
//	DIZGIN_DEBUG=1   — process-local verbose mode.
//	DIZGIN_DEBUG=all — process-local AND propagated to every subprocess
//	                 dizgin / dizgind spawn (broker passes the env var
//	                 along when invoking runhcs / dizgin-init).
//
// Verbose() is a no-op when neither is set; the framework adds zero
// extra lines / files / subprocesses in production.
//
// Thread-safe: all functions use fmt.Fprintf which is goroutine-safe.
package log

import (
	"fmt"
	"os"
	"strings"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// Subsystem constants for use with DebugSub and IsDebugEnabled.
const (
	SubContainer = "container"
	SubBroker    = "broker"
	SubMount     = "mount"
	SubEnv       = "env"
	SubPTY       = "pty"
	SubNet       = "net"
	SubInit      = "init"
)

// Quiet suppresses Info and Warn output when true (set via DIZGIN_QUIET=1).
var Quiet bool

// debugEnabled controls the legacy Debug() function. True only when DIZGIN_DEBUG=1 or DIZGIN_DEBUG=all.
var debugEnabled bool

// verboseEnabled is the master switch for the structured debug
// framework (PreflightWindows, Verbose() emitters, classifier
// surface). True when DIZGIN_DEBUG is set to any non-selective value
// ("1" or "all"). Selective subsystem mode (DIZGIN_DEBUG=container,mount)
// keeps Verbose silent because the user opted into per-subsystem output
// only.
var verboseEnabled bool

// verbosePropagate is true when DIZGIN_DEBUG=all. Subprocess-spawning
// callers (broker -> runhcs, dizgin -> dizgin-init) check this to decide
// whether to forward the env var into the child's environment.
var verbosePropagate bool

// debugSubs controls DebugSub and IsDebugEnabled.
// nil  = debug disabled entirely
// {}   = all subsystems enabled (DIZGIN_DEBUG=1 or all)
// {k}  = only listed subsystems enabled (DIZGIN_DEBUG=container,mount)
var debugSubs map[string]bool

func init() {
	Quiet = os.Getenv(brand.Env("QUIET")) == "1"
	raw := os.Getenv(brand.Env("DEBUG"))
	switch raw {
	case "1":
		debugEnabled = true
		verboseEnabled = true
		debugSubs = map[string]bool{} // empty = all subsystems
	case "all":
		debugEnabled = true
		verboseEnabled = true
		verbosePropagate = true
		debugSubs = map[string]bool{}
	default:
		if raw != "" {
			// Selective subsystem mode: DebugSub() works; legacy Debug() is silent.
			debugSubs = make(map[string]bool)
			for s := range strings.SplitSeq(raw, ",") {
				if s = strings.TrimSpace(s); s != "" {
					debugSubs[s] = true
				}
			}
		}
	}
}

// EnableVerbose flips the master verbose switch on at runtime. Used by
// callers that read the persistent setting from ~/.dizgin/config.yaml
// (cfg.Setup.Debug) — the env var alone covers ad-hoc invocations,
// while the persistent flag is for users that want verbose by default
// without exporting DIZGIN_DEBUG in their shell. Idempotent.
func EnableVerbose(propagate bool) {
	verboseEnabled = true
	debugEnabled = true
	if debugSubs == nil {
		debugSubs = map[string]bool{}
	}
	if propagate {
		verbosePropagate = true
	}
}

// IsVerbose reports whether the verbose framework is active.
// PreflightWindows / Aggregator / Verbose() short-circuit on false.
func IsVerbose() bool { return verboseEnabled }

// VerbosePropagate reports whether DIZGIN_DEBUG=all (or equivalent) was
// set. Callers that spawn subprocesses use this to decide whether to
// inject DIZGIN_DEBUG=all into the child environment so the entire
// process chain (broker -> runhcs -> dizgin-init) becomes verbose
// together under one switch.
func VerbosePropagate() bool { return verbosePropagate }

// emit formats msg with args, runs the formatted string through the
// secret scrubber, and writes prefix+msg+"\n" to stderr. Centralising
// the scrub here means every public log helper (Error/Warn/Info/Debug
// /Verbose/DebugSub) inherits redaction by construction — no caller
// can accidentally bypass it by reaching for fmt.Fprintf directly.
func emit(prefix, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, prefix+ScrubSecrets(msg))
}

// Error prints a formatted error message to stderr. Always visible.
func Error(format string, args ...any) {
	emit(brand.Name+": error: ", format, args...)
}

// Warn prints a formatted warning to stderr unless Quiet is set.
func Warn(format string, args ...any) {
	if !Quiet {
		emit(brand.Name+": ", format, args...)
	}
}

// Info prints a formatted informational message to stderr unless Quiet is set.
func Info(format string, args ...any) {
	if !Quiet {
		emit(brand.Name+": ", format, args...)
	}
}

// Debug prints a formatted debug message to stderr when DIZGIN_DEBUG=1.
func Debug(format string, args ...any) {
	if debugEnabled {
		emit(brand.Name+": debug: ", format, args...)
	}
}

// Verbose prints a structured framework message to stderr when verbose
// mode is on. Tagged with `[layer:phase]` so a reader can spot which
// component emitted the line at a glance — broker, dizgin, dizgin-init,
// runhcs, etc. The single integer compare on verboseEnabled means
// production callers pay zero cost (no format-string allocation, no
// I/O) when the framework is off.
//
// Example:
//
//	log.Verbose("dizgin:phase", "sandbox-create backend=%s", name)
func Verbose(tag, format string, args ...any) {
	if !verboseEnabled {
		return
	}
	emit(fmt.Sprintf(brand.Name+": verbose[%s]: ", tag), format, args...)
}

// DebugSub prints a debug message tagged with a subsystem name.
// Visible when DIZGIN_DEBUG=1 (all subsystems) or DIZGIN_DEBUG=<sub>[,<sub>...] (selective).
func DebugSub(sub, format string, args ...any) {
	if debugSubs == nil {
		return
	}
	if len(debugSubs) > 0 && !debugSubs[sub] {
		return
	}
	emit(fmt.Sprintf(brand.Name+": debug[%s]: ", sub), format, args...)
}

// IsDebugEnabled reports whether debug output is active for the given subsystem.
func IsDebugEnabled(sub string) bool {
	if debugSubs == nil {
		return false
	}
	return len(debugSubs) == 0 || debugSubs[sub]
}

// timingEnabled is the evaluated-once result of the DIZGIN_PHASE_TIMING check.
// Shared by dizgin main, the restricted backend, and acl_windows so the
// three sites stay in sync without re-reading the env on every call.
var timingEnabled = os.Getenv(brand.Env("PHASE_TIMING")) == "1" || os.Getenv(brand.Env("DEBUG")) == "all"

// IsTimingEnabled reports whether phase timing is active (DIZGIN_PHASE_TIMING=1
// or DIZGIN_DEBUG=all). The result is evaluated once at program startup.
func IsTimingEnabled() bool { return timingEnabled }
