// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"fmt"
	"io"
	"strings"
)

// PrintLearnSummary writes a user-facing summary of captured access-
// denial lines to w. Called from box.Wait after the child exits and
// the stderr recorder has flushed any partial tail.
//
// Empty input prints a "no denials captured" line so the user knows
// the recorder ran and produced no surprises (rather than thinking
// learn mode silently failed).
func PrintLearnSummary(w io.Writer, hits []string) {
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "==== dizgin --learn summary ====")
	if len(hits) == 0 {
		fmt.Fprintln(w, "No access-denial messages captured during this session.")
		fmt.Fprintln(w, "Either the tool did not attempt to read any sensitive")
		fmt.Fprintln(w, "paths, or its denial output did not match a recognised")
		fmt.Fprintln(w, "locale pattern (case-insensitive: \"access denied\",")
		fmt.Fprintln(w, "\"permission denied\", \"operation not permitted\", or")
		fmt.Fprintln(w, "locale variants like \"engellendi\" / \"verweigert\" /")
		fmt.Fprintln(w, "\"denegado\").")
		fmt.Fprintln(w, "")
		return
	}
	fmt.Fprintf(w, "Captured %d access-denial line(s):\n", len(hits))
	for i, h := range hits {
		line := strings.TrimSpace(h)
		// Truncate very long lines so the summary stays readable even
		// when a tool dumps a verbose error with embedded stack.
		if len(line) > 200 {
			line = line[:197] + "..."
		}
		fmt.Fprintf(w, "  [%d] %s\n", i+1, line)
	}
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Lines referencing a path under your sensitive DENY set")
	fmt.Fprintln(w, "(.ssh, .aws/credentials, .gnupg, DPAPI vault, browser cookies, …)")
	fmt.Fprintln(w, "are expected — the iter6 backend blocks those by design.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "If stdin is a TTY, dizgin will now ask you to classify each path")
	fmt.Fprintln(w, "(rw / ro / deny / skip) and persist the decisions to")
	fmt.Fprintln(w, "~/.dizgin/permissions/<tool>.yaml. Subsequent runs auto-load that")
	fmt.Fprintln(w, "file so you only see the prompt once per tool. Re-run --learn")
	fmt.Fprintln(w, "to overwrite, edit the file directly to tweak, or delete it to")
	fmt.Fprintln(w, "revert to the SSOT default.")
	fmt.Fprintln(w, "")
}
