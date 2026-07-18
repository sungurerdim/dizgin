// SPDX-License-Identifier: MIT

package platform

import (
	"runtime"
	"testing"
)

func TestBackendForOS(t *testing.T) {
	cases := []struct {
		goos string
		want string
	}{
		{"windows", "restricted"},
		{"darwin", "seatbelt"},
		{"linux", "bubblewrap"},
	}

	for _, tc := range cases {
		t.Run(tc.goos, func(t *testing.T) {
			got, err := BackendForOS(tc.goos)
			if err != nil {
				t.Fatalf("BackendForOS(%q) error: %v", tc.goos, err)
			}
			if got != tc.want {
				t.Errorf("BackendForOS(%q) = %q, want %q", tc.goos, got, tc.want)
			}
		})
	}
}

func TestBackendForOSUnsupported(t *testing.T) {
	_, err := BackendForOS("plan9")
	if err == nil {
		t.Fatal("expected error for unsupported OS, got nil")
	}
}

func TestBackendName(t *testing.T) {
	// BackendName must succeed on the current CI host.
	name, err := BackendName()
	if err != nil {
		t.Fatalf("BackendName() error: %v (GOOS=%s)", err, runtime.GOOS)
	}
	if name == "" {
		t.Error("BackendName() returned empty string")
	}
}

func TestBackendName_ReturnsForCurrentOS(t *testing.T) {
	name, err := BackendName()
	if err != nil {
		t.Fatalf("BackendName() error: %v", err)
	}

	// Verify the returned name matches what BackendForOS would return for
	// the current runtime.GOOS.
	want, err := BackendForOS(runtime.GOOS)
	if err != nil {
		t.Fatalf("BackendForOS(%q) error: %v", runtime.GOOS, err)
	}
	if name != want {
		t.Errorf("BackendName() = %q, want %q (GOOS=%s)", name, want, runtime.GOOS)
	}

	// On Windows CI, specifically verify "restricted" — the iter6
	// sole production path (CreateRestrictedToken + Medium IL + Job +
	// per-child mitigation policy + DACL DENY on sensitive paths).
	if runtime.GOOS == "windows" && name != "restricted" {
		t.Errorf("on Windows: want %q, got %q", "restricted", name)
	}
}

func TestPlatformInfo(t *testing.T) {
	// Verify the platform has non-empty OS and architecture values.
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	if goos == "" {
		t.Error("runtime.GOOS is empty")
	}
	if goarch == "" {
		t.Error("runtime.GOARCH is empty")
	}

	// BackendName must succeed for any supported platform where tests run.
	name, err := BackendName()
	if err != nil {
		t.Fatalf("BackendName() error on %s/%s: %v", goos, goarch, err)
	}
	if name == "" {
		t.Errorf("BackendName() returned empty on %s/%s", goos, goarch)
	}
}
