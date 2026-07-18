// SPDX-License-Identifier: MIT

package log

import (
	"os"
	"strings"
	"testing"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// captureStderr redirects os.Stderr to a pipe, calls fn, then returns
// whatever was written. Restores the original stderr before returning.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w

	fn()

	_ = w.Close()
	os.Stderr = origStderr

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	_ = r.Close()
	return string(buf[:n])
}

func TestError_AlwaysOutputs(t *testing.T) {
	Quiet = false
	debugEnabled = false

	got := captureStderr(t, func() {
		Error("something broke")
	})

	if got != brand.Name+": error: something broke\n" {
		t.Errorf("Error output = %q, want %q", got, brand.Name+": error: something broke\n")
	}
}

func TestError_OutputsEvenWhenQuiet(t *testing.T) {
	Quiet = true
	debugEnabled = false

	got := captureStderr(t, func() {
		Error("still visible")
	})

	if !strings.Contains(got, "still visible") {
		t.Errorf("Error should output even when Quiet=true, got %q", got)
	}
}

func TestError_FormatArgs(t *testing.T) {
	Quiet = false
	debugEnabled = false

	got := captureStderr(t, func() {
		Error("code %d: %s", 42, "failed")
	})

	want := brand.Name + ": error: code 42: failed\n"
	if got != want {
		t.Errorf("Error output = %q, want %q", got, want)
	}
}

func TestWarn_OutputsWhenNotQuiet(t *testing.T) {
	Quiet = false
	debugEnabled = false

	got := captureStderr(t, func() {
		Warn("heads up")
	})

	want := brand.Name + ": heads up\n"
	if got != want {
		t.Errorf("Warn output = %q, want %q", got, want)
	}
}

func TestWarn_SilentWhenQuiet(t *testing.T) {
	Quiet = true
	debugEnabled = false

	got := captureStderr(t, func() {
		Warn("should not appear")
	})

	if got != "" {
		t.Errorf("Warn should be silent when Quiet=true, got %q", got)
	}
}

func TestInfo_OutputsWhenNotQuiet(t *testing.T) {
	Quiet = false
	debugEnabled = false

	got := captureStderr(t, func() {
		Info("status %s", "ok")
	})

	want := brand.Name + ": status ok\n"
	if got != want {
		t.Errorf("Info output = %q, want %q", got, want)
	}
}

func TestInfo_SilentWhenQuiet(t *testing.T) {
	Quiet = true
	debugEnabled = false

	got := captureStderr(t, func() {
		Info("should not appear")
	})

	if got != "" {
		t.Errorf("Info should be silent when Quiet=true, got %q", got)
	}
}

func TestDebug_OutputsWhenEnabled(t *testing.T) {
	Quiet = false
	debugEnabled = true

	got := captureStderr(t, func() {
		Debug("trace %d", 1)
	})

	want := brand.Name + ": debug: trace 1\n"
	if got != want {
		t.Errorf("Debug output = %q, want %q", got, want)
	}
}

func TestDebug_SilentWhenDisabled(t *testing.T) {
	Quiet = false
	debugEnabled = false

	got := captureStderr(t, func() {
		Debug("should not appear")
	})

	if got != "" {
		t.Errorf("Debug should be silent when debugEnabled=false, got %q", got)
	}
}

func TestDebugSub_All(t *testing.T) {
	orig := debugSubs
	t.Cleanup(func() { debugSubs = orig })

	// DIZGIN_DEBUG=1 equivalent: empty map = all subsystems.
	debugSubs = map[string]bool{}

	got := captureStderr(t, func() {
		DebugSub(SubContainer, "layer found at %s", `C:\layers\ns`)
		DebugSub(SubMount, "total mounts: %d", 3)
	})

	if !strings.Contains(got, "debug[container]") {
		t.Errorf("expected container subsystem output, got %q", got)
	}
	if !strings.Contains(got, "debug[mount]") {
		t.Errorf("expected mount subsystem output, got %q", got)
	}
}

func TestDebugSub_Selective(t *testing.T) {
	orig := debugSubs
	t.Cleanup(func() { debugSubs = orig })

	// DIZGIN_DEBUG=container equivalent: only container subsystem enabled.
	debugSubs = map[string]bool{SubContainer: true}

	var got string
	got = captureStderr(t, func() {
		DebugSub(SubContainer, "create: success")
	})
	if !strings.Contains(got, "debug[container]") {
		t.Errorf("expected container output with selective filter, got %q", got)
	}

	got = captureStderr(t, func() {
		DebugSub(SubMount, "total mounts: 5")
	})
	if got != "" {
		t.Errorf("expected no mount output with container-only filter, got %q", got)
	}
}

func TestDebugSub_Disabled(t *testing.T) {
	orig := debugSubs
	t.Cleanup(func() { debugSubs = orig })

	debugSubs = nil // disabled

	got := captureStderr(t, func() {
		DebugSub(SubContainer, "should not appear")
		DebugSub(SubMount, "should not appear")
	})
	if got != "" {
		t.Errorf("expected no output when debug disabled, got %q", got)
	}
}

func TestIsDebugEnabled(t *testing.T) {
	orig := debugSubs
	t.Cleanup(func() { debugSubs = orig })

	// nil → nothing enabled
	debugSubs = nil
	if IsDebugEnabled(SubContainer) {
		t.Error("IsDebugEnabled(container) = true, want false when disabled")
	}

	// empty → all enabled
	debugSubs = map[string]bool{}
	if !IsDebugEnabled(SubContainer) {
		t.Error("IsDebugEnabled(container) = false, want true when all enabled")
	}
	if !IsDebugEnabled(SubMount) {
		t.Error("IsDebugEnabled(mount) = false, want true when all enabled")
	}

	// selective → only listed
	debugSubs = map[string]bool{SubContainer: true}
	if !IsDebugEnabled(SubContainer) {
		t.Error("IsDebugEnabled(container) = false, want true (listed)")
	}
	if IsDebugEnabled(SubMount) {
		t.Error("IsDebugEnabled(mount) = true, want false (not listed)")
	}
}

func TestVerbose_SilentWhenDisabled(t *testing.T) {
	orig := verboseEnabled
	t.Cleanup(func() { verboseEnabled = orig })
	verboseEnabled = false

	got := captureStderr(t, func() {
		Verbose("dizgin:phase", "should not appear")
	})
	if got != "" {
		t.Errorf("Verbose should be silent when verboseEnabled=false, got %q", got)
	}
}

func TestVerbose_OutputsWhenEnabled(t *testing.T) {
	orig := verboseEnabled
	t.Cleanup(func() { verboseEnabled = orig })
	verboseEnabled = true

	got := captureStderr(t, func() {
		Verbose("dizgin:phase", "loaded %d profiles", 7)
	})
	want := brand.Name + ": verbose[dizgin:phase]: loaded 7 profiles\n"
	if got != want {
		t.Errorf("Verbose output = %q, want %q", got, want)
	}
}

func TestEnableVerbose_FlipsSwitchAndPropagateWhenAsked(t *testing.T) {
	origV, origD, origP, origSubs := verboseEnabled, debugEnabled, verbosePropagate, debugSubs
	t.Cleanup(func() {
		verboseEnabled = origV
		debugEnabled = origD
		verbosePropagate = origP
		debugSubs = origSubs
	})
	verboseEnabled = false
	debugEnabled = false
	verbosePropagate = false
	debugSubs = nil

	EnableVerbose(false)
	if !IsVerbose() {
		t.Error("IsVerbose should return true after EnableVerbose")
	}
	if !debugEnabled {
		t.Error("EnableVerbose should also flip debugEnabled")
	}
	if VerbosePropagate() {
		t.Error("VerbosePropagate should stay false when EnableVerbose(false)")
	}
	if debugSubs == nil {
		t.Error("EnableVerbose should initialize debugSubs to a non-nil empty map")
	}

	EnableVerbose(true)
	if !VerbosePropagate() {
		t.Error("VerbosePropagate should be true after EnableVerbose(true)")
	}
}

func TestOutputPrefix(t *testing.T) {
	Quiet = false
	debugEnabled = true

	tests := []struct {
		name   string
		fn     func()
		prefix string
	}{
		{"Error", func() { Error("x") }, brand.Name + ": error: "},
		{"Warn", func() { Warn("x") }, brand.Name + ": "},
		{"Info", func() { Info("x") }, brand.Name + ": "},
		{"Debug", func() { Debug("x") }, brand.Name + ": debug: "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := captureStderr(t, tt.fn)
			if !strings.HasPrefix(got, tt.prefix) {
				t.Errorf("%s output %q does not start with %q", tt.name, got, tt.prefix)
			}
		})
	}
}
