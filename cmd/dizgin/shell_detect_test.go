// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sungurerdim/dizgin/internal/brand"
)

func TestLooksLikeMSYSConvertedArg(t *testing.T) {
	cases := []struct {
		arg  string
		want bool
	}{
		{"/c", true},    // canonical MSYS-converted token
		{"/d", true},    // another short flag
		{"/Z", true},    // uppercase letter still matches
		{"/", false},    // bare slash is not arg
		{"/cd", false},  // two letters — not converted
		{"/tmp", false}, // looks like a Unix path, ignored
		{"-c", false},   // dash flag, not slash
		{"", false},     // empty
		{"/1", false},   // digit, not letter
		{"//c", false},  // double slash, not single-letter
	}
	for _, c := range cases {
		got := looksLikeMSYSConvertedArg(c.arg)
		if got != c.want {
			t.Errorf("looksLikeMSYSConvertedArg(%q) = %v, want %v", c.arg, got, c.want)
		}
	}
}

func TestWarnIfMSYSConversionRisk_OptOut(t *testing.T) {
	t.Setenv("MSYSTEM", "MINGW64")
	t.Setenv(brand.Env("NO_SHELL_DETECT"), "1")

	var buf bytes.Buffer
	warnIfMSYSConversionRisk(&buf, []string{"cmd", "/c", "echo"})

	if buf.Len() != 0 {
		t.Fatalf("DIZGIN_NO_SHELL_DETECT=1 should silence warnings, got: %s", buf.String())
	}
}

func TestWarnIfMSYSConversionRisk_NoShell_NoOutput(t *testing.T) {
	// Clear all detection markers so the function decides "not MSYS".
	t.Setenv("MSYSTEM", "")
	t.Setenv("MSYS_ROOT", "")
	t.Setenv("OSTYPE", "")
	t.Setenv(brand.Env("NO_SHELL_DETECT"), "")

	var buf bytes.Buffer
	warnIfMSYSConversionRisk(&buf, []string{"cmd", "/c", "echo"})

	if buf.Len() != 0 {
		t.Fatalf("non-MSYS shell should not warn, got: %s", buf.String())
	}
}

func TestWarnIfMSYSConversionRisk_MSYSWithSuspectArg(t *testing.T) {
	t.Setenv("MSYSTEM", "MINGW64")
	t.Setenv(brand.Env("NO_SHELL_DETECT"), "")

	var buf bytes.Buffer
	warnIfMSYSConversionRisk(&buf, []string{"cmd", "/c", "echo", "hello"})

	out := buf.String()
	if !strings.Contains(out, "dizgin run") {
		t.Fatalf("expected 'dizgin run' remediation hint, got: %s", out)
	}
	if !strings.Contains(out, "/c") {
		t.Fatalf("expected suspect arg in warning, got: %s", out)
	}
}

func TestWarnIfMSYSConversionRisk_MSYSNoSuspectArg(t *testing.T) {
	t.Setenv("MSYSTEM", "MINGW64")
	t.Setenv(brand.Env("NO_SHELL_DETECT"), "")

	var buf bytes.Buffer
	warnIfMSYSConversionRisk(&buf, []string{"node", "-e", "console.log(1)"})

	if buf.Len() != 0 {
		t.Fatalf("MSYS shell with no /letter args should not warn, got: %s", buf.String())
	}
}

func TestWarnIfCmdShellWithSwitches_TriggersOnCmdSlashC(t *testing.T) {
	t.Setenv(brand.Env("NO_SHELL_DETECT"), "")
	var buf bytes.Buffer
	warnIfCmdShellWithSwitches(&buf, "cmd", []string{"/c", "echo hello"})
	out := buf.String()
	if !strings.Contains(out, "dizgin run") {
		t.Fatalf("expected 'dizgin run' remediation hint for cmd /c, got: %s", out)
	}
}

func TestWarnIfCmdShellWithSwitches_TriggersOnCmdExeSlashK(t *testing.T) {
	t.Setenv(brand.Env("NO_SHELL_DETECT"), "")
	var buf bytes.Buffer
	warnIfCmdShellWithSwitches(&buf, "cmd.exe", []string{"/k", "echo persistent"})
	if !strings.Contains(buf.String(), "dizgin run") {
		t.Fatalf("expected hint for cmd.exe /k, got: %s", buf.String())
	}
}

func TestWarnIfCmdShellWithSwitches_QuietForNonCmd(t *testing.T) {
	t.Setenv(brand.Env("NO_SHELL_DETECT"), "")
	var buf bytes.Buffer
	warnIfCmdShellWithSwitches(&buf, "powershell", []string{"-c", "echo hi"})
	if buf.Len() != 0 {
		t.Fatalf("powershell -c must not trigger cmd /c warning, got: %s", buf.String())
	}
}

func TestWarnIfCmdShellWithSwitches_OptOut(t *testing.T) {
	t.Setenv(brand.Env("NO_SHELL_DETECT"), "1")
	var buf bytes.Buffer
	warnIfCmdShellWithSwitches(&buf, "cmd", []string{"/c", "echo"})
	if buf.Len() != 0 {
		t.Fatalf("DIZGIN_NO_SHELL_DETECT=1 should silence cmd /c warning, got: %s", buf.String())
	}
}

func TestDetectMSYS_MarkerSet(t *testing.T) {
	cases := []struct {
		name      string
		envKey    string
		envVal    string
		wantMatch bool
	}{
		{"MSYSTEM mingw64", "MSYSTEM", "MINGW64", true},
		{"MSYSTEM ucrt64", "MSYSTEM", "UCRT64", true},
		{"MSYS_ROOT path", "MSYS_ROOT", "/c/msys64", true},
		{"OSTYPE cygwin", "OSTYPE", "cygwin", true},
		{"OSTYPE msys", "OSTYPE", "msys", true},
		{"OSTYPE linux-gnu", "OSTYPE", "linux-gnu", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("MSYSTEM", "")
			t.Setenv("MSYS_ROOT", "")
			t.Setenv("OSTYPE", "")
			t.Setenv(c.envKey, c.envVal)
			if got := detectMSYS(); got != c.wantMatch {
				t.Errorf("detectMSYS() with %s=%q = %v, want %v",
					c.envKey, c.envVal, got, c.wantMatch)
			}
		})
	}
}
