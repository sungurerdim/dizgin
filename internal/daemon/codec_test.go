// SPDX-License-Identifier: MIT

package daemon

import (
	"bytes"
	"io"
	"testing"
)

func TestCodecAllMessageTypes(t *testing.T) {
	messages := []Message{
		{Type: TypeRegister, ID: "r1", Tool: "claude", Workdir: "/w", Backend: "container", PID: 100},
		{Type: TypeHeartbeat, ID: "r1", Status: "running", Snippet: "hello", Memory: 4096},
		{Type: TypeDeregister, ID: "r1", Exit: 42},
		{Type: TypeCommand, ID: "r1", Action: ActionSuspend},
		{Type: TypeQueryStatus},
		{Type: TypeShutdown},
	}

	pr, pw := io.Pipe()
	enc := NewEncoder(pw)
	dec := NewDecoder(pr)

	// Writer goroutine.
	go func() {
		for _, m := range messages {
			if err := enc.Encode(m); err != nil {
				break
			}
		}
		_ = pw.Close()
	}()

	for i, want := range messages {
		var got Message
		if err := dec.Decode(&got); err != nil {
			t.Fatalf("message %d (%s): decode error: %v", i, want.Type, err)
		}
		if got.Type != want.Type {
			t.Errorf("message %d: type want %q, got %q", i, want.Type, got.Type)
		}
		if got.ID != want.ID {
			t.Errorf("message %d (%s): id want %q, got %q", i, want.Type, want.ID, got.ID)
		}
		if got.Tool != want.Tool {
			t.Errorf("message %d (%s): tool want %q, got %q", i, want.Type, want.Tool, got.Tool)
		}
		if got.Action != want.Action {
			t.Errorf("message %d (%s): action want %q, got %q", i, want.Type, want.Action, got.Action)
		}
		if got.Exit != want.Exit {
			t.Errorf("message %d (%s): exit want %d, got %d", i, want.Type, want.Exit, got.Exit)
		}
		if got.PID != want.PID {
			t.Errorf("message %d (%s): pid want %d, got %d", i, want.Type, want.PID, got.PID)
		}
	}
}

func TestCodecRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	dec := NewDecoder(&buf)

	msg := Message{
		Type:    TypeRegister,
		ID:      "sess-1",
		PID:     42,
		Tool:    "claude",
		Workdir: "/home/user/project",
		Backend: "container",
	}

	if err := enc.Encode(msg); err != nil {
		t.Fatalf("encode: %v", err)
	}

	var got Message
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if got.Type != msg.Type {
		t.Errorf("Type: got %q, want %q", got.Type, msg.Type)
	}
	if got.ID != msg.ID {
		t.Errorf("ID: got %q, want %q", got.ID, msg.ID)
	}
	if got.PID != msg.PID {
		t.Errorf("PID: got %d, want %d", got.PID, msg.PID)
	}
	if got.Tool != msg.Tool {
		t.Errorf("Tool: got %q, want %q", got.Tool, msg.Tool)
	}
}

func TestCodecMultipleMessages(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	dec := NewDecoder(&buf)

	types := []MessageType{TypeRegister, TypeHeartbeat, TypeDeregister}
	for _, mt := range types {
		if err := enc.Encode(Message{Type: mt, ID: "x"}); err != nil {
			t.Fatalf("encode %q: %v", mt, err)
		}
	}

	for _, want := range types {
		var msg Message
		if err := dec.Decode(&msg); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if msg.Type != want {
			t.Errorf("got %q, want %q", msg.Type, want)
		}
	}
}

func TestCodecEOF(t *testing.T) {
	var buf bytes.Buffer
	dec := NewDecoder(&buf)
	var msg Message
	err := dec.Decode(&msg)
	if err != io.EOF {
		t.Errorf("expected io.EOF, got %v", err)
	}
}

func TestCodecInstancesField(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	dec := NewDecoder(&buf)

	instances := []InstanceInfo{
		{ID: "s1", Tool: "claude", Status: StatusRunning},
		{ID: "s2", Tool: "aider", Status: StatusSuspended},
	}
	msg := Message{Type: TypeStatus, Instances: instances}

	if err := enc.Encode(msg); err != nil {
		t.Fatalf("encode: %v", err)
	}

	var got Message
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(got.Instances) != 2 {
		t.Fatalf("got %d sessions, want 2", len(got.Instances))
	}
	if got.Instances[0].ID != "s1" || got.Instances[1].ID != "s2" {
		t.Errorf("sessions mismatch: %+v", got.Instances)
	}
}
