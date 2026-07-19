// SPDX-License-Identifier: MIT

package main

import (
	"slices"
	"testing"
)

func TestBuildPassthroughEnv_Empty(t *testing.T) {
	if got := buildPassthroughEnv(nil); got != nil {
		t.Errorf("got %v, want nil for empty passthrough list", got)
	}
}

// TestBuildPassthroughEnv_Wildcard is a regression test for the "*" escape
// hatch: it must return the FULL host environment, not a filtered subset —
// a partial match here would silently narrow what tools relying on "*"
// actually receive.
func TestBuildPassthroughEnv_Wildcard(t *testing.T) {
	t.Setenv("DIZGIN_TEST_WILDCARD_VAR", "wildcard-value")
	got := buildPassthroughEnv([]string{"*"})
	found := false
	for _, kv := range got {
		if kv == "DIZGIN_TEST_WILDCARD_VAR=wildcard-value" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("wildcard passthrough missing DIZGIN_TEST_WILDCARD_VAR; got %d entries", len(got))
	}
}

// TestBuildPassthroughEnv_SkipsUnsetVars verifies a named var that is absent
// (or empty) from the host environment is silently dropped rather than
// passed through as "KEY=" — an empty override could shadow a real default
// set later in the profile-env merge chain.
func TestBuildPassthroughEnv_SkipsUnsetVars(t *testing.T) {
	got := buildPassthroughEnv([]string{"DIZGIN_TEST_DOES_NOT_EXIST_VAR"})
	if len(got) != 0 {
		t.Errorf("got %v, want empty (unset var must not appear as KEY=)", got)
	}
}

func TestBuildPassthroughEnv_NamedSubset(t *testing.T) {
	t.Setenv("DIZGIN_TEST_A", "va")
	t.Setenv("DIZGIN_TEST_B", "vb")
	got := buildPassthroughEnv([]string{"DIZGIN_TEST_A", "DIZGIN_TEST_MISSING"})
	if !slices.Contains(got, "DIZGIN_TEST_A=va") {
		t.Errorf("got %v, want it to contain DIZGIN_TEST_A=va", got)
	}
	if slices.Contains(got, "DIZGIN_TEST_B=vb") {
		t.Errorf("got %v, want it to NOT contain DIZGIN_TEST_B (not requested)", got)
	}
}
