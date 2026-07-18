// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mattn/go-isatty"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/security"
)

// learn_interactive_windows.go — iter6 Phase D interactive prompt.
//
// After the child exits in --learn mode, dizgin calls PromptForPermissions
// for each unique path the access-denial recorder captured. The user
// chooses one of:
//
//   [RW]   full read-write exemption — DENY ACE skipped on next run.
//   [RO]   read-only exemption — DENY ACE skipped, future tightening
//          may add a real read-only shim.
//   [DENY] keep the DENY in place — also remembered so the path is not
//          re-prompted next session.
//   [SKIP] do not record a decision — path will surface again next run.
//
// Non-TTY contexts (piped stdin, CI, cron) default every entry to SKIP
// so the prompt cannot hang an unattended job. The captured paths are
// still reported in the summary above; the user can re-run interactively
// to set decisions.

// PromptForPermissions iterates paths and asks the user to classify
// each. Returns an updated Overrides combining existing + new
// decisions. When stdin is not a terminal the function reports the
// skip and returns existing unchanged.
//
// w is the prompt sink (typically os.Stderr so the prompt lands on
// the same stream the summary already used). r is the input source
// (typically os.Stdin); the bufio.Reader internalizes buffering so
// the caller does not have to.
func PromptForPermissions(w io.Writer, r io.Reader, paths []string, existing Overrides) Overrides {
	out := Overrides{
		RW:   append([]string{}, existing.RW...),
		RO:   append([]string{}, existing.RO...),
		Deny: append([]string{}, existing.Deny...),
	}

	if len(paths) == 0 {
		return out
	}
	if !isStdinTTY() {
		fmt.Fprintln(w, brand.Name+": stdin not a TTY — skipping interactive permission prompt")
		fmt.Fprintln(w, brand.Name+": re-run with --learn from an interactive shell to record decisions")
		return out
	}

	reader := bufio.NewReader(r)
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "==== Interactive permission decisions ====")
	fmt.Fprintln(w, "For each path the tool tried to access, choose:")
	fmt.Fprintln(w, "  rw   — allow read AND write (full exemption)")
	fmt.Fprintln(w, "  ro   — allow read only")
	fmt.Fprintln(w, "  deny — keep DENY (remembered so you are not asked again)")
	fmt.Fprintln(w, "  skip — no decision (path will be re-prompted next session)")
	fmt.Fprintln(w, "")

	for i, p := range paths {
		choice := promptOne(w, reader, i+1, len(paths), p)
		switch choice {
		case "rw":
			if !sliceContainsFold(out.RW, p) {
				out.RW = append(out.RW, p)
			}
		case "ro":
			if !sliceContainsFold(out.RO, p) {
				out.RO = append(out.RO, p)
			}
		case "deny":
			if !sliceContainsFold(out.Deny, p) {
				out.Deny = append(out.Deny, p)
			}
		case "skip":
			// no-op
		}
	}
	fmt.Fprintln(w, "")
	return normaliseOverrides(out)
}

// promptOne presents the choice list for one path and re-prompts until
// the user enters a recognised verb. Empty line → "skip" (the safest
// default — leaves the user's prior decision, if any, untouched).
func promptOne(w io.Writer, r *bufio.Reader, idx, total int, path string) string {
	display := path
	if len(display) > 100 {
		display = "..." + display[len(display)-97:]
	}
	for {
		fmt.Fprintf(w, "[%d/%d] %s\n", idx, total, display)
		// Extra confirmation on credential-shaped paths so a misclick
		// does not silently expose ~/.ssh to the tool.
		if security.IsSensitiveDeny(path) {
			fmt.Fprintln(w, "  [!] this path holds credential material — "+
				"only choose 'rw' if you intentionally want the tool to write to it")
		}
		fmt.Fprint(w, "  choice [rw/ro/deny/skip]: ")
		line, err := r.ReadString('\n')
		if err != nil && err != io.EOF {
			fmt.Fprintf(w, "  dizgin: input error %v — defaulting to skip\n", err)
			return "skip"
		}
		choice := strings.ToLower(strings.TrimSpace(line))
		switch choice {
		case "":
			return "skip"
		case "rw", "ro", "deny", "skip":
			return choice
		default:
			fmt.Fprintf(w, "  dizgin: unknown choice %q — please enter rw, ro, deny, or skip\n", choice)
			if err == io.EOF {
				return "skip"
			}
		}
	}
}

// isStdinTTY reports whether os.Stdin is connected to a terminal. The
// check uses isatty.IsTerminal directly so piped or redirected stdin
// produces false (the unattended-skip path). Cygwin terminals are
// reported as TTYs only when the user runs dizgin from a real conpty;
// piped MSYS2 stdin still degrades to skip.
func isStdinTTY() bool {
	return isatty.IsTerminal(os.Stdin.Fd()) ||
		isatty.IsCygwinTerminal(os.Stdin.Fd())
}

// sliceContainsFold reports whether s contains target under case-
// insensitive Windows-style comparison.
func sliceContainsFold(s []string, target string) bool {
	for _, v := range s {
		if strings.EqualFold(v, target) {
			return true
		}
	}
	return false
}
