// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/security"
)

// defaultSuggestModel is the Anthropic model used for the `dizgin add-path
// --suggest` LLM enrichment step. Keeping it as a named const makes it
// easy to locate and update without searching through literal strings.
// Override at runtime with $DIZGIN_SUGGEST_MODEL (e.g. to pin a specific
// model snapshot without a rebuild).
const defaultSuggestModel = "claude-haiku-4-5"

// suggestModel returns the model to use for --suggest, honoring
// $DIZGIN_SUGGEST_MODEL when set.
func suggestModel() string {
	if m := os.Getenv("DIZGIN_SUGGEST_MODEL"); m != "" {
		return m
	}
	return defaultSuggestModel
}

// runAddPathSuggest powers `dizgin add-path --suggest <path>...`.
//
// For each supplied path it gathers fast metadata (existence, type,
// SSOT membership, system / user-profile location) and emits a
// suggestion of which mode (rw / ro / deny / skip) to grant. When
// `$ANTHROPIC_API_KEY` is present the suggestion is enriched with a
// single round trip to Claude Haiku; without the key the command
// falls back to a purely heuristic recommendation so it still works
// offline.
//
// The command is *advisory only* — no profile YAML is written. The
// user copies the recommended `dizgin add-path ...` invocation if they
// agree. This keeps `--suggest` safe to run on unfamiliar paths
// without committing to a permission change.
//
// Cost / privacy notes:
//
//   - The LLM call uses the user's own Anthropic API key — cost
//     falls on the user's account.
//   - Only the absolute path, its kind (file / dir / missing), and
//     a small set of derived booleans (sensitive? system? exists?)
//     are sent. The file's *contents* are never read or transmitted.
//   - Network policy: 30 s timeout, no streaming, no retries, single
//     POST to api.anthropic.com per path.
func runAddPathSuggest(paths []string, tool string) error {
	if len(paths) == 0 {
		return fmt.Errorf("add-path --suggest: no path supplied")
	}
	// DIZGIN_NO_SUGGEST=1 disables the LLM enrichment call to api.anthropic.com,
	// consistent with DIZGIN_NO_WFP and DIZGIN_NO_DAEMON_AUTOSTART kill switches.
	// Set this if you need fully offline / air-gapped operation.
	noSuggest := os.Getenv(brand.Env("NO_SUGGEST")) == "1"
	apiKey := strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY"))
	switch {
	case noSuggest:
		apiKey = "" // treat as unset — heuristic only
		fmt.Fprintln(os.Stderr, brand.Name+": DIZGIN_NO_SUGGEST=1 — using heuristic suggestions only")
		fmt.Fprintln(os.Stderr, "")
	case apiKey == "":
		fmt.Fprintln(os.Stderr, brand.Name+": ANTHROPIC_API_KEY not set — using heuristic suggestions only")
		fmt.Fprintln(os.Stderr, "")
	default:
		fmt.Fprintln(os.Stderr, brand.Name+": --suggest sends each absolute path (which may reveal your OS username), its kind, and a few derived booleans to api.anthropic.com — file contents are never read or transmitted. Set DIZGIN_NO_SUGGEST=1 to use heuristic-only suggestions.")
		fmt.Fprintln(os.Stderr, "")
	}

	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ! %s: %v\n", p, err)
			continue
		}
		c := buildPathContext(abs)
		fmt.Fprintf(os.Stdout, "── %s ──\n", abs)
		fmt.Fprintf(os.Stdout, "  type:      %s\n", c.kind)
		fmt.Fprintf(os.Stdout, "  category:  %s\n", c.category)
		fmt.Fprintf(os.Stdout, "  exists:    %v\n", c.exists)
		if c.size > 0 {
			fmt.Fprintf(os.Stdout, "  size:      %d bytes\n", c.size)
		}

		heur := heuristicSuggestion(c)
		fmt.Fprintf(os.Stdout, "  heuristic: %s — %s\n", heur.mode, heur.reason)

		final := heur
		if apiKey != "" {
			llm, err := callAnthropicSuggest(apiKey, c, tool)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  dizgin: LLM error: %v (using heuristic only)\n", err)
			} else {
				fmt.Fprintf(os.Stdout, "  LLM:       %s — %s\n", llm.mode, llm.reason)
				// Prefer the LLM verdict only when it agrees with the
				// heuristic on the safety-critical "deny" axis. Demoting
				// a heuristic "deny" to "rw" on LLM advice would silently
				// expose a credential surface — never do that.
				if heur.mode != "deny" || llm.mode == "deny" {
					final = llm
				}
			}
		}

		fmt.Fprintln(os.Stdout, "  next step:")
		switch final.mode {
		case "rw":
			fmt.Fprintf(os.Stdout, "    dizgin add-path --tool %s %s\n", tool, abs)
		case "ro":
			fmt.Fprintf(os.Stdout, "    dizgin add-path --tool %s --ro %s\n", tool, abs)
		case "deny", "skip":
			fmt.Fprintln(os.Stdout, "    leave unchanged (do not add to profile)")
		default:
			fmt.Fprintf(os.Stdout, "    (unknown mode %q — refusing to recommend)\n", final.mode)
		}
		fmt.Fprintln(os.Stdout, "")
	}
	return nil
}

// pathContext holds the deterministic, side-effect-free metadata
// `runAddPathSuggest` derives before recommending a mode. It is the
// only state the LLM sees — `pathContext` is the privacy boundary.
type pathContext struct {
	abs         string
	kind        string // file / dir / missing
	category    string // sensitive / system / user-profile / other
	size        int64
	exists      bool
	isSensitive bool
}

func buildPathContext(abs string) pathContext {
	c := pathContext{abs: abs, kind: "missing"}
	info, err := os.Stat(abs)
	if err == nil {
		c.exists = true
		if info.IsDir() {
			c.kind = "dir"
		} else {
			c.kind = "file"
			c.size = info.Size()
		}
	}
	if security.IsSensitiveDeny(abs) {
		c.isSensitive = true
		c.category = "sensitive (SSOT credential surface)"
		return c
	}
	lower := strings.ToLower(filepath.Clean(abs))
	switch {
	case strings.HasPrefix(lower, `c:\windows`):
		c.category = "system"
	case strings.HasPrefix(lower, `c:\program files`):
		c.category = "system"
	case strings.HasPrefix(lower, `c:\programdata`):
		c.category = "system"
	default:
		home := strings.ToLower(os.Getenv("USERPROFILE"))
		if home != "" && strings.HasPrefix(lower, home) {
			c.category = "user-profile"
		} else {
			c.category = "other"
		}
	}
	return c
}

// suggestion is one mode + free-text reason. Used uniformly for the
// heuristic and the LLM path so the caller does not branch on origin.
type suggestion struct {
	mode   string // rw / ro / deny / skip
	reason string
}

// heuristicSuggestion derives a mode from path category alone — no
// LLM, no network. Captures the obvious cases so `--suggest` is
// usable offline and gives a defensible recommendation when the LLM
// round trip fails or no API key is configured.
func heuristicSuggestion(c pathContext) suggestion {
	if c.isSensitive {
		return suggestion{mode: "deny", reason: "sensitive SSOT — must not appear in a profile"}
	}
	if !c.exists {
		return suggestion{mode: "skip", reason: "path does not exist; nothing to expose"}
	}
	switch c.category {
	case "system":
		return suggestion{mode: "ro", reason: "system path — read-only typical for shared tools"}
	case "user-profile":
		return suggestion{mode: "rw", reason: "user-profile path — read-write typical for project state"}
	default:
		return suggestion{mode: "rw", reason: "no specific category match — default to read-write"}
	}
}

// callAnthropicSuggest posts a small messages-API request and parses
// the response into a single suggestion. The model is told to return
// ONLY a JSON object, so the parser can be strict.
//
// Failure surface: network error, non-200 status, empty body,
// unparseable JSON, unknown mode literal. All surface as an error
// and the caller falls back to the heuristic.
func callAnthropicSuggest(apiKey string, c pathContext, tool string) (suggestion, error) {
	const endpoint = "https://api.anthropic.com/v1/messages"
	prompt := buildLLMSuggestPrompt(c, tool)

	body := map[string]any{
		"model":      suggestModel(),
		"max_tokens": 256,
		"messages": []map[string]any{
			{"role": "user", "content": prompt},
		},
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return suggestion{}, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return suggestion{}, err
	}
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return suggestion{}, fmt.Errorf("POST: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(resp.Body)
		return suggestion{}, fmt.Errorf("status %d: %s",
			resp.StatusCode, strings.TrimSpace(buf.String()))
	}
	var apiResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return suggestion{}, fmt.Errorf("decode: %w", err)
	}
	if len(apiResp.Content) == 0 || apiResp.Content[0].Text == "" {
		return suggestion{}, fmt.Errorf("empty response")
	}
	return parseLLMSuggestion(apiResp.Content[0].Text)
}

// buildLLMSuggestPrompt produces the user-message text for the
// Anthropic messages call. Every field included is also a field
// `pathContext` derives locally — see the privacy boundary note on
// `runAddPathSuggest`.
func buildLLMSuggestPrompt(c pathContext, tool string) string {
	var sb strings.Builder
	sb.WriteString("You are advising on DIZGIN sandbox profile permissions.\n\n")
	fmt.Fprintf(&sb, "Tool: %s\nPath: %s\nKind: %s\nCategory: %s\nExists: %v\n",
		tool, c.abs, c.kind, c.category, c.exists)
	if c.isSensitive {
		sb.WriteString("\nNote: this path is in the DIZGIN sensitive SSOT (credential surface). The safe default is 'deny'.\n")
	}
	sb.WriteString("\nWhich access mode should the tool get?\n")
	sb.WriteString("  rw   read + write\n")
	sb.WriteString("  ro   read only\n")
	sb.WriteString("  deny keep DENY in place (typical for credentials)\n")
	sb.WriteString("  skip no decision\n\n")
	sb.WriteString(`Respond with ONLY a single-line JSON object: {"mode":"<one of rw/ro/deny/skip>","reason":"<short justification, max 120 chars>"}`)
	sb.WriteString("\n")
	return sb.String()
}

// parseLLMSuggestion extracts the JSON object the prompt asked for.
// Loose extraction: finds the first `{` and last `}` and parses what
// sits between — so a model prefix like "Here is my answer:" is
// tolerated. The mode literal is whitelisted.
func parseLLMSuggestion(text string) (suggestion, error) {
	start := strings.IndexByte(text, '{')
	end := strings.LastIndexByte(text, '}')
	if start < 0 || end <= start {
		return suggestion{}, fmt.Errorf("no JSON object in response: %q", strings.TrimSpace(text))
	}
	var parsed struct {
		Mode   string `json:"mode"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(text[start:end+1]), &parsed); err != nil {
		return suggestion{}, fmt.Errorf("decode JSON: %w", err)
	}
	switch parsed.Mode {
	case "rw", "ro", "deny", "skip":
		return suggestion{mode: parsed.Mode, reason: parsed.Reason}, nil
	default:
		return suggestion{}, fmt.Errorf("unknown mode %q", parsed.Mode)
	}
}
