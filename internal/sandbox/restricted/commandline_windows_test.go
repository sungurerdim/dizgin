// SPDX-License-Identifier: MIT

//go:build windows

package restricted

// TST-20 — escapeArg / buildCommandLine command-line escaping.
//
// These are pure string functions — fully testable with no OS side-effects.
// The escaping rules mirror os/exec's escapeArg on Windows (CommandLineToArgvW
// convention): args containing spaces, tabs, or embedded quotes are wrapped in
// double-quotes with backslash-escaping inside.

import (
	"strings"
	"testing"
)

// ---- escapeArg unit tests ----

func TestEscapeArg_PlainWordUnchanged(t *testing.T) {
	cases := []string{"hello", "world", "go", "build", "--version", "foo123"}
	for _, c := range cases {
		got := escapeArg(c)
		if got != c {
			t.Errorf("escapeArg(%q) = %q; plain word should be unchanged", c, got)
		}
	}
}

func TestEscapeArg_EmptyStringBecomesQuotedPair(t *testing.T) {
	got := escapeArg("")
	if got != `""` {
		t.Errorf("escapeArg(%q) = %q; want %q", "", got, `""`)
	}
}

func TestEscapeArg_SpaceTriggersQuoting(t *testing.T) {
	got := escapeArg("hello world")
	if !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, `"`) {
		t.Errorf("escapeArg with space should be quoted; got %q", got)
	}
	// Must round-trip: the outer quotes wrap the original content.
	inner := got[1 : len(got)-1]
	if inner != "hello world" {
		t.Errorf("inner content mangled: %q", inner)
	}
}

func TestEscapeArg_TabTriggersQuoting(t *testing.T) {
	got := escapeArg("tab\there")
	if !strings.HasPrefix(got, `"`) {
		t.Errorf("escapeArg with tab should be quoted; got %q", got)
	}
}

func TestEscapeArg_EmbeddedQuoteEscaped(t *testing.T) {
	// A lone double-quote char must become \"
	got := escapeArg(`say "hello"`)
	if !strings.Contains(got, `\"`) {
		t.Errorf("embedded quote not escaped in %q", got)
	}
	// Must be wrapped in outer quotes.
	if !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, `"`) {
		t.Errorf("result should be double-quoted; got %q", got)
	}
}

func TestEscapeArg_BackslashBeforeQuoteDoubled(t *testing.T) {
	// `path\"` → the backslash before the embedded quote must be doubled.
	// Input: a backslash immediately before a double-quote.
	got := escapeArg(`C:\path\"file"`)
	// Verify it contains \\\" (one escaped backslash + escaped quote).
	if !strings.Contains(got, `\\\"`) {
		t.Errorf("backslash before embedded quote not doubled: %q", got)
	}
}

func TestEscapeArg_TrailingBackslashesDoubledWhenQuoted(t *testing.T) {
	// "foo bar\" → trailing backslash must be doubled so the outer closing
	// quote is not accidentally escaped.
	got := escapeArg(`foo bar\`)
	if !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, `"`) {
		t.Fatalf("should be quoted; got %q", got)
	}
	// The content inside quotes must end with \\ (doubled trailing backslash).
	inner := got[1 : len(got)-1]
	if !strings.HasSuffix(inner, `\\`) {
		t.Errorf("trailing backslash not doubled; inner=%q", inner)
	}
}

func TestEscapeArg_MultipleSpacesPreserved(t *testing.T) {
	input := "a   b"
	got := escapeArg(input)
	if !strings.HasPrefix(got, `"`) {
		t.Fatalf("should be quoted; got %q", got)
	}
	inner := got[1 : len(got)-1]
	if inner != input {
		t.Errorf("multiple spaces mangled: got %q, want %q", inner, input)
	}
}

func TestEscapeArg_WindowsAbsolutePath_NoQuoting(t *testing.T) {
	// An ordinary Windows absolute path with no spaces or quotes needs no quoting.
	input := `C:\Windows\System32\cmd.exe`
	got := escapeArg(input)
	if got != input {
		t.Errorf("plain Windows path should not be quoted: got %q", got)
	}
}

func TestEscapeArg_WindowsPathWithSpaces(t *testing.T) {
	input := `C:\Program Files\Git\bin\git.exe`
	got := escapeArg(input)
	if !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, `"`) {
		t.Errorf("Windows path with spaces should be quoted; got %q", got)
	}
}

func TestEscapeArg_UnicodeArg(t *testing.T) {
	// A Unicode argument with no whitespace/quotes should pass through unchanged.
	input := "フォルダー名"
	got := escapeArg(input)
	if got != input {
		t.Errorf("Unicode arg without spaces should be unchanged; got %q, want %q", got, input)
	}
}

func TestEscapeArg_UnicodeArgWithSpace(t *testing.T) {
	input := "フォルダー 名"
	got := escapeArg(input)
	if !strings.HasPrefix(got, `"`) {
		t.Errorf("Unicode arg with space should be quoted; got %q", got)
	}
}

// ---- absExe unit tests ----

func TestAbsExe_EmptyReturnsError(t *testing.T) {
	_, err := absExe("")
	if err == nil {
		t.Error("empty command should return an error")
	}
}

func TestAbsExe_AlreadyAbsoluteReturnedUnchanged(t *testing.T) {
	input := `C:\Windows\System32\cmd.exe`
	got, err := absExe(input)
	if err != nil {
		t.Fatalf("absExe(%q): %v", input, err)
	}
	if got != input {
		t.Errorf("absolute path should be returned unchanged; got %q", got)
	}
}

func TestAbsExe_RelativeNotOnDiskReturnedAsIs(t *testing.T) {
	// A relative name that doesn't exist on disk should come back as-is
	// (absExe falls through when stat fails).
	got, err := absExe("definitely-not-a-real-binary-xyzzy")
	if err != nil {
		t.Fatalf("absExe on non-existent relative name: %v", err)
	}
	if got != "definitely-not-a-real-binary-xyzzy" {
		t.Errorf("non-existent relative name should pass through; got %q", got)
	}
}

// ---- utf16Env unit tests ----

func TestUTF16Env_Empty(t *testing.T) {
	buf, err := utf16Env(nil)
	if err != nil {
		t.Fatalf("utf16Env(nil): %v", err)
	}
	// Must produce at least the double-NUL terminator (one uint16 of value 0).
	if len(buf) == 0 {
		t.Error("utf16Env(nil) must produce at least a NUL terminator")
	}
	if buf[len(buf)-1] != 0 {
		t.Error("utf16Env buffer must end with 0")
	}
}

func TestUTF16Env_SingleEntry(t *testing.T) {
	buf, err := utf16Env([]string{"PATH=C:\\Windows\\System32"})
	if err != nil {
		t.Fatalf("utf16Env single entry: %v", err)
	}
	if len(buf) == 0 {
		t.Fatal("empty buffer for single env entry")
	}
	if buf[len(buf)-1] != 0 {
		t.Error("buffer must end with NUL terminator")
	}
}

func TestUTF16Env_MultipleEntries(t *testing.T) {
	env := []string{
		"DIZGIN_TEST=1",
		"USERPROFILE=C:\\Users\\testuser",
		"TEMP=C:\\Users\\testuser\\AppData\\Local\\Temp",
	}
	buf, err := utf16Env(env)
	if err != nil {
		t.Fatalf("utf16Env multiple entries: %v", err)
	}
	if len(buf) == 0 {
		t.Fatal("empty buffer")
	}
	if buf[len(buf)-1] != 0 {
		t.Error("buffer must end with NUL terminator")
	}
}

func TestUTF16Env_UnicodeValue(t *testing.T) {
	env := []string{"NAME=テストユーザー"}
	buf, err := utf16Env(env)
	if err != nil {
		t.Fatalf("utf16Env with unicode value: %v", err)
	}
	if len(buf) == 0 {
		t.Fatal("empty buffer for unicode env entry")
	}
}
