// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"
	"strings"
	"unicode"
)

// handleRunSubcommand splits cmdLine into argv and re-invokes the
// normal dizgin run path with the result. Bypasses MSYS path conversion
// because the user typed the entire command as ONE quoted string —
// MSYS only converts unquoted /letter tokens, so a quoted "cmd /c X"
// passes through bash intact, lands here, and gets split AFTER the
// shell has had its chance.
//
// Splitter scope: handles double-quoted, single-quoted, and unquoted
// whitespace-separated tokens. Backslash escapes inside double quotes.
// Does NOT do globbing, brace expansion, command substitution, or
// environment-variable expansion — `dizgin run` is a literal-arg
// transport, not a shell. If users need those, they can reach for
// MSYS_NO_PATHCONV=1 instead.
//
// Returns the same exit code semantics as the normal run path:
//   - 0 / 1 — tool exit, fed back to the caller.
//   - exitToolError on parse failure with stderr context.
func handleRunSubcommand(cmdLine string) error {
	tokens, err := splitCommandLine(cmdLine)
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}
	if len(tokens) == 0 {
		return fmt.Errorf("run: empty command line")
	}
	// Re-enter the standard run() flow with the parsed tokens taking
	// the place of os.Args[1:]. We pass nil for cmd to avoid a
	// package-init cycle (rootCmd's RunE is run, so referencing
	// rootCmd here would close the loop). run() guards the
	// cmd-dependent branches against nil — completion is
	// intentionally not supported through `dizgin run`.
	return run(nil, tokens)
}

// splitCommandLine tokenises a shell-ish command string into argv.
// State machine deliberately small: top-level whitespace separates
// tokens, single-quotes preserve everything literally, double-quotes
// allow backslash escapes for the four POSIX-portable cases (\\ \" \$
// \`). Returns (tokens, err) where err identifies the column of an
// unterminated quote.
func splitCommandLine(s string) ([]string, error) {
	var (
		tokens   []string
		current  strings.Builder
		inSingle bool
		inDouble bool
	)
	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, current.String())
			current.Reset()
		}
	}
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case inSingle:
			if r == '\'' {
				inSingle = false
				continue
			}
			current.WriteRune(r)
		case inDouble:
			if r == '\\' && i+1 < len(runes) {
				next := runes[i+1]
				switch next {
				case '\\', '"', '$', '`':
					current.WriteRune(next)
					i++
					continue
				}
				current.WriteRune(r)
				continue
			}
			if r == '"' {
				inDouble = false
				continue
			}
			current.WriteRune(r)
		case r == '\'':
			inSingle = true
		case r == '"':
			inDouble = true
		case unicode.IsSpace(r):
			flush()
		default:
			current.WriteRune(r)
		}
	}
	if inSingle {
		return nil, fmt.Errorf("unterminated single quote")
	}
	if inDouble {
		return nil, fmt.Errorf("unterminated double quote")
	}
	flush()
	return tokens, nil
}

// runSubcommandUsage prints help for `dizgin run`. Kept separate from
// printUsage() so the top-level help stays focused on the common path.
func runSubcommandUsage() {
	fmt.Fprintln(os.Stderr, `dizgin run "<command line>"

Run a single quoted command line through dizgin. The command line is
parsed by dizgin's own splitter, NOT by the host shell — this is the
escape hatch for Git Bash / MSYS2 / Cygwin where path conversion
would mangle arguments like /c, /b, /d.

Examples:
  dizgin run "cmd /c echo hello"
  dizgin run "node -e 'console.log(1)'"
  dizgin run "ANTHROPIC_API_KEY=sk-... claude --print hello"

Notes:
  - Quote the entire argument so your host shell does not pre-process it.
  - Single quotes preserve content literally; double quotes support
    standard backslash escapes for backslash, double-quote, dollar, and backtick.
  - No globbing, brace expansion, or command substitution. If you need
    those, use the host shell with MSYS_NO_PATHCONV=1 instead.`)
}
