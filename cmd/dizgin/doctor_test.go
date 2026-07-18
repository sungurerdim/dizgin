// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderDoctorHuman_AllPass(t *testing.T) {
	checks := []doctorCheck{
		{Name: "config load", Status: doctorPass, Summary: "OK"},
		{Name: "profiles load", Status: doctorPass, Summary: "29 loaded"},
	}
	var buf bytes.Buffer
	renderDoctorHuman(&buf, checks)
	out := buf.String()

	if !strings.Contains(out, "[ OK ] config load") {
		t.Errorf("missing OK marker: %s", out)
	}
	if !strings.Contains(out, "all checks passed") {
		t.Errorf("missing summary: %s", out)
	}
}

func TestRenderDoctorHuman_FailWithHint(t *testing.T) {
	checks := []doctorCheck{
		{
			Name:    "daemon reachable",
			Status:  doctorFail,
			Summary: "pipe closed",
			Hint:    "run: dizgind start",
		},
	}
	var buf bytes.Buffer
	renderDoctorHuman(&buf, checks)
	out := buf.String()

	if !strings.Contains(out, "[FAIL] daemon reachable") {
		t.Errorf("missing FAIL marker: %s", out)
	}
	if !strings.Contains(out, "hint: run: dizgind start") {
		t.Errorf("missing hint line: %s", out)
	}
	if !strings.Contains(out, "1 check(s) failed") {
		t.Errorf("missing failure summary: %s", out)
	}
}

func TestRenderDoctorHuman_SkipShown(t *testing.T) {
	checks := []doctorCheck{
		{Name: "appcontainer smoke", Status: doctorSkip, Summary: "Windows-only"},
	}
	var buf bytes.Buffer
	renderDoctorHuman(&buf, checks)
	if !strings.Contains(buf.String(), "[SKIP] appcontainer smoke") {
		t.Errorf("missing SKIP marker: %s", buf.String())
	}
}

func TestCountFails(t *testing.T) {
	checks := []doctorCheck{
		{Status: doctorPass},
		{Status: doctorFail},
		{Status: doctorSkip},
		{Status: doctorFail},
	}
	if got := countFails(checks); got != 2 {
		t.Errorf("countFails = %d, want 2", got)
	}
}

func TestRunDoctor_UnknownFlagErrors(t *testing.T) {
	if err := runDoctor([]string{"--bogus"}); err == nil {
		t.Fatalf("expected error on unknown flag, got nil")
	}
}

func TestCheckProfilesLoad_PicksUpBundled(t *testing.T) {
	c := checkProfilesLoad()
	if c.Status != doctorPass {
		t.Fatalf("expected pass with bundled profiles, got %s: %s", c.Status, c.Summary)
	}
	if !strings.Contains(c.Summary, "tool profile(s) loaded") {
		t.Errorf("unexpected summary: %s", c.Summary)
	}
}
