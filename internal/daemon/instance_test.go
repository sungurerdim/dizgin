// SPDX-License-Identifier: MIT

package daemon

import (
	"testing"
	"time"
)

func TestRegistryRegisterAndGet(t *testing.T) {
	r := NewRegistry()
	inst := &Instance{InstanceData: InstanceData{ID: "a", Tool: "claude", Status: StatusRunning}}
	r.Register(inst)

	got := r.Get("a")
	if got == nil {
		t.Fatal("Get returned nil")
		return
	}
	if got.Tool != "claude" {
		t.Errorf("Tool=%q", got.Tool)
	}
}

func TestRegistryGetUnknown(t *testing.T) {
	r := NewRegistry()
	if got := r.Get("nonexistent"); got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestRegistryRemove(t *testing.T) {
	r := NewRegistry()
	r.Register(&Instance{InstanceData: InstanceData{ID: "b", Status: StatusRunning}})

	removed := r.Remove("b")
	if removed == nil {
		t.Fatal("Remove returned nil")
	}
	if r.Get("b") != nil {
		t.Error("instance still present after Remove")
	}
}

func TestRegistryRemoveNonexistent(t *testing.T) {
	r := NewRegistry()
	if got := r.Remove("nope"); got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestRegistryUpdate(t *testing.T) {
	r := NewRegistry()
	r.Register(&Instance{InstanceData: InstanceData{ID: "c", Status: StatusRunning}})

	ok := r.Update("c", Message{
		Type:    TypeHeartbeat,
		ID:      "c",
		Snippet: "hello world",
		Memory:  1024,
		CPU:     12.5,
		PIDs:    3,
	})
	if !ok {
		t.Fatal("Update returned false")
	}

	inst := r.Get("c")
	if inst.LastSnippet != "hello world" {
		t.Errorf("Snippet=%q", inst.LastSnippet)
	}
	if inst.MemoryBytes != 1024 {
		t.Errorf("MemoryBytes=%d", inst.MemoryBytes)
	}
}

func TestRegistryUpdateUnknown(t *testing.T) {
	r := NewRegistry()
	ok := r.Update("unknown", Message{Type: TypeHeartbeat})
	if ok {
		t.Error("Update should return false for unknown instance")
	}
}

func TestRegistrySnapshots(t *testing.T) {
	r := NewRegistry()
	r.Register(&Instance{InstanceData: InstanceData{ID: "x", Tool: "aider", Status: StatusRunning}})
	r.Register(&Instance{InstanceData: InstanceData{ID: "y", Tool: "codex", Status: StatusRunning}})

	snaps := r.Snapshots()
	if len(snaps) != 2 {
		t.Fatalf("got %d snapshots, want 2", len(snaps))
	}
}

func TestRegistryInfos(t *testing.T) {
	r := NewRegistry()
	r.Register(&Instance{InstanceData: InstanceData{ID: "i1", Tool: "claude", Status: StatusRunning, PID: 999}})

	infos := r.Infos()
	if len(infos) != 1 {
		t.Fatalf("got %d infos, want 1", len(infos))
	}
	if infos[0].ID != "i1" || infos[0].PID != 999 {
		t.Errorf("info mismatch: %+v", infos[0])
	}
}

func TestRegistryPruneDeadInstances(t *testing.T) {
	r := NewRegistry()
	inst := &Instance{InstanceData: InstanceData{ID: "dead", Status: StatusRunning}}
	r.Register(inst)

	// Artificially age the heartbeat past the timeout.
	inst.mu.Lock()
	inst.LastHeartbeat = time.Now().Add(-2 * heartbeatTimeout)
	inst.mu.Unlock()

	r.PruneDeadInstances()
	if r.Get("dead") != nil {
		t.Error("dead instance should have been pruned")
	}
}

func TestInstanceSnapshot(t *testing.T) {
	inst := &Instance{InstanceData: InstanceData{
		ID:      "snap-test",
		Tool:    "claude",
		Workdir: "/projects/foo",
		Status:  StatusRunning,
	}}
	s := inst.Snapshot()
	if s.ID != inst.ID {
		t.Errorf("ID: got %q, want %q", s.ID, inst.ID)
	}
	if s.Tool != inst.Tool {
		t.Errorf("Tool: got %q, want %q", s.Tool, inst.Tool)
	}
	if s.Workdir != inst.Workdir {
		t.Errorf("Workdir: got %q, want %q", s.Workdir, inst.Workdir)
	}
}

func TestInstanceInfo(t *testing.T) {
	inst := &Instance{InstanceData: InstanceData{
		ID:       "info-test",
		PID:      1234,
		Tool:     "claude",
		Status:   StatusRunning,
		ExitCode: 0,
	}}
	info := inst.Info()
	if info.ID != "info-test" || info.PID != 1234 || info.Tool != "claude" {
		t.Errorf("info mismatch: %+v", info)
	}
	if info.Status != StatusRunning {
		t.Errorf("status=%q", info.Status)
	}
}

func TestInstanceIsDead(t *testing.T) {
	inst := &Instance{InstanceData: InstanceData{ID: "live"}}
	inst.LastHeartbeat = time.Now()
	if inst.isDead() {
		t.Error("fresh instance should not be dead")
	}

	inst.LastHeartbeat = time.Now().Add(-2 * heartbeatTimeout)
	if !inst.isDead() {
		t.Error("stale instance should be dead")
	}
}
