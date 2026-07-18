// SPDX-License-Identifier: MIT

package brand

import (
	"strings"
	"testing"
)

// The constants below are hand-written because Go const expressions
// cannot call strings.ToUpper. These tests guard the derivations so a
// future rename cannot leave EnvPrefix (or a derived identifier) stale.
func TestDerivedConstantsStayInSync(t *testing.T) {
	if want := strings.ToUpper(Name) + "_"; EnvPrefix != want {
		t.Errorf("EnvPrefix = %q, want %q (derived from Name)", EnvPrefix, want)
	}
	if want := Name + "d"; DaemonName != want {
		t.Errorf("DaemonName = %q, want %q", DaemonName, want)
	}
	if want := "." + Name; DotDir != want {
		t.Errorf("DotDir = %q, want %q", DotDir, want)
	}
	if want := `\\.\pipe\` + DaemonName; PipeName != want {
		t.Errorf("PipeName = %q, want %q", PipeName, want)
	}
	if want := DaemonName + ".sock"; SocketFile != want {
		t.Errorf("SocketFile = %q, want %q", SocketFile, want)
	}
}

func TestName_LowercaseSingleToken(t *testing.T) {
	if Name == "" || Name != strings.ToLower(Name) || strings.ContainsAny(Name, " /\\.") {
		t.Errorf("Name = %q, want a non-empty lowercase single token", Name)
	}
}

func TestEnv(t *testing.T) {
	if got, want := Env("NO_WFP"), EnvPrefix+"NO_WFP"; got != want {
		t.Errorf("Env(NO_WFP) = %q, want %q", got, want)
	}
}
