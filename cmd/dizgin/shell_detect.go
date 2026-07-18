// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// detectMSYS reports whether dizgin is running under a Git Bash / MSYS2 /
// Cygwin shell that performs path-style argument conversion. Detection
// is environment-variable based — the shells set distinctive markers
// that survive subprocess spawn.
//
// Recognized markers (any one is enough):
//   - MSYSTEM       — set by MSYS2/MinGW shells (e.g. "MINGW64", "UCRT64")
//   - MSYS_ROOT     — set by some MSYS2 builds, paired with MSYSTEM
//   - OSTYPE=cygwin or msys — Cygwin and Bash for Windows variants
//
// A blank match means no conversion shell — guard rail short-circuits.
func detectMSYS() bool {
	if os.Getenv("MSYSTEM") != "" {
		return true
	}
	if os.Getenv("MSYS_ROOT") != "" {
		return true
	}
	if t := strings.ToLower(os.Getenv("OSTYPE")); strings.HasPrefix(t, "cygwin") || strings.HasPrefix(t, "msys") {
		return true
	}
	return false
}

// looksLikeMSYSConvertedArg reports whether arg has the shape that
// MSYS path-conversion mangles: a leading slash followed by exactly
// one ASCII letter (e.g. "/c", "/b") which MSYS rewrites as "C:\…".
//
// Real Unix paths like "/tmp" or "/usr/bin" have more than one
// character after the slash, so they do not trigger. Multi-letter
// flags like "/help" also don't trigger — MSYS doesn't convert
// those either.
func looksLikeMSYSConvertedArg(arg string) bool {
	if len(arg) != 2 {
		return false
	}
	if arg[0] != '/' {
		return false
	}
	c := arg[1]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// warnIfMSYSConversionRisk inspects toolArgs for /letter-shaped
// arguments under an MSYS shell and emits a one-time stderr warning
// suggesting the bypass options. Opt-out via DIZGIN_NO_SHELL_DETECT=1.
//
// Why warn instead of error: MSYS conversion is best-effort detection
// — false positives (a tool that legitimately accepts /letter args
// somehow surviving conversion) should not block the user. The
// warning gives them the hint and gets out of the way.
func warnIfMSYSConversionRisk(out io.Writer, toolArgs []string) {
	if os.Getenv(brand.Env("NO_SHELL_DETECT")) == "1" {
		return
	}
	if !detectMSYS() {
		return
	}
	suspect := ""
	for _, a := range toolArgs {
		if looksLikeMSYSConvertedArg(a) {
			suspect = a
			break
		}
	}
	if suspect == "" {
		return
	}
	_, _ = fmt.Fprintf(out, brand.Name+": %s may have mangled %q — try: dizgin run \"<command line>\" (silence: DIZGIN_NO_SHELL_DETECT=1)\n",
		msysShellLabel(), suspect)
}

// warnIfCmdShellWithSwitches detects `dizgin -- cmd /c ...` style argv
// where the user is wrapping a Windows command-processor switch. cmd's
// /C and /K re-parse the joined remainder under their own rules — the
// argv we hand to CreateProcessW gets quoted by the kernel, the
// resulting string isn't always what cmd wants, and the symptom is a
// silent interactive shell instead of the intended one-shot.
//
// `dizgin run "<line>"` sidesteps this because it passes the literal
// command line straight through. We surface that as the canonical fix
// rather than try to second-guess cmd's quoting rules in argv land.
// Opt-out via DIZGIN_NO_SHELL_DETECT=1.
func warnIfCmdShellWithSwitches(out io.Writer, toolBin string, toolArgs []string) {
	if os.Getenv(brand.Env("NO_SHELL_DETECT")) == "1" {
		return
	}
	base := strings.ToLower(toolBin)
	if base != "cmd" && base != "cmd.exe" {
		return
	}
	if len(toolArgs) < 2 {
		return
	}
	first := strings.ToLower(toolArgs[0])
	if first != "/c" && first != "/k" {
		return
	}
	_, _ = fmt.Fprintf(out, brand.Name+": cmd %s argv re-parse may run interactive — try: dizgin run %q (silence: DIZGIN_NO_SHELL_DETECT=1)\n",
		toolArgs[0], toolBin+" "+strings.Join(toolArgs, " "))
}

// msysShellLabel returns a human-friendly description of which MSYS
// flavor was detected. Used purely for the warning text.
func msysShellLabel() string {
	if v := os.Getenv("MSYSTEM"); v != "" {
		return "Git Bash / " + v
	}
	if t := strings.ToLower(os.Getenv("OSTYPE")); strings.HasPrefix(t, "cygwin") {
		return "Cygwin"
	}
	if t := strings.ToLower(os.Getenv("OSTYPE")); strings.HasPrefix(t, "msys") {
		return "MSYS"
	}
	return "MSYS-class"
}
