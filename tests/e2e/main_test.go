// SPDX-License-Identifier: MIT

//go:build integration

package e2e

import (
	"os"
	"testing"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// TestMain configures the e2e suite environment before any test runs.
//
//   - DIZGIN_NO_DAEMON_AUTOSTART=1 prevents dizgin from blocking up to 15 s
//     waiting for the dizgind daemon when the test environment does
//     not provide one. Tests that need the daemon are responsible for
//     starting it themselves.
//   - DIZGIN_DISABLE_PATH_MOUNTS=1 stops dizgin from icacls-stamping every
//     directory in the host PATH. On a developer machine with 30+ PATH
//     entries the cold-run icacls cost is over 100 s and dwarfs the
//     test workload itself. The integration suite does not exercise
//     PATH-resolved binaries, so disabling this is safe.
//
// Both overrides are applied via os.Setenv (not t.Setenv) so they
// inherit to every exec.Command spawned by the suite, including
// subprocess dizgin runs that read the env at process start.
func TestMain(m *testing.M) {
	if os.Getenv(brand.Env("NO_DAEMON_AUTOSTART")) == "" {
		_ = os.Setenv(brand.Env("NO_DAEMON_AUTOSTART"), "1")
	}
	if os.Getenv(brand.Env("DISABLE_PATH_MOUNTS")) == "" {
		_ = os.Setenv(brand.Env("DISABLE_PATH_MOUNTS"), "1")
	}
	os.Exit(m.Run())
}
