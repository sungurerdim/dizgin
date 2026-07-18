// SPDX-License-Identifier: MIT

//go:build windows

package wct

import (
	"os"
	"strings"
	"testing"
)

func TestDiagnoseHang_SelfProcess(t *testing.T) {
	pid := uint32(os.Getpid())
	chains, err := DiagnoseHang(pid)
	if err != nil {
		t.Fatalf("DiagnoseHang(self): %v", err)
	}
	if len(chains) == 0 {
		t.Fatal("expected at least one thread; got 0")
	}
	for _, c := range chains {
		if c.ThreadID == 0 {
			t.Errorf("thread chain has zero TID: %+v", c)
		}
	}
}

func TestDiagnoseHang_NonexistentPid(t *testing.T) {
	chains, err := DiagnoseHang(0xFFFFFFFE)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(chains) != 0 {
		t.Errorf("expected empty chains for nonexistent pid; got %d", len(chains))
	}
}

func TestObjTypeString_KnownAndUnknown(t *testing.T) {
	cases := map[uint32]string{
		1:   "critsec",
		3:   "mutex",
		4:   "alpc",
		8:   "thread",
		11:  "socket-io",
		99:  "type-99",
		0:   "type-0",
		255: "type-255",
	}
	for in, want := range cases {
		if got := objTypeString(in); got != want {
			t.Errorf("objTypeString(%d): got %q, want %q", in, got, want)
		}
	}
}

func TestStatusString_KnownAndUnknown(t *testing.T) {
	cases := map[uint32]string{
		2:  "running",
		3:  "blocked",
		6:  "owned",
		8:  "abandoned",
		99: "status-99",
	}
	for in, want := range cases {
		if got := statusString(in); got != want {
			t.Errorf("statusString(%d): got %q, want %q", in, got, want)
		}
	}
}

func TestFormatThreadChain_RendersAllFields(t *testing.T) {
	tc := ThreadWaitChain{
		ThreadID: 1234,
		Cycle:    true,
		Nodes: []WaitChainNode{
			{ObjectType: "mutex", Status: "blocked", Name: "\\Foo\\Bar"},
			{ObjectType: "thread", Status: "running", OwnerPID: 5678, OwnerTID: 9012, WaitMs: 42},
		},
	}
	got := FormatThreadChain(tc)
	if !strings.Contains(got, "tid=1234") {
		t.Errorf("missing tid; got: %s", got)
	}
	if !strings.Contains(got, "(CYCLE)") {
		t.Errorf("missing cycle marker; got: %s", got)
	}
	if !strings.Contains(got, `name="\\Foo\\Bar"`) {
		t.Errorf("missing object name; got: %s", got)
	}
	if !strings.Contains(got, "owner_pid=5678") {
		t.Errorf("missing owner PID; got: %s", got)
	}
	if !strings.Contains(got, "wait_ms=42") {
		t.Errorf("missing wait_ms; got: %s", got)
	}
}
