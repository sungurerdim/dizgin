// SPDX-License-Identifier: MIT

package sandbox

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/sungurerdim/dizgin/internal/config"
)

// mockBackend is a minimal Backend used in tests.
type mockBackend struct {
	name      string
	available bool
}

func (m *mockBackend) Name() string    { return m.name }
func (m *mockBackend) Available() bool { return m.available }
func (m *mockBackend) Create(_ context.Context, _ *config.Config, _ CreateOpts) (Box, error) {
	return &mockBox{}, nil
}

// mockBox is a minimal Box used in tests.
type mockBox struct{}

func (b *mockBox) Start(_ context.Context, _ string, _ []string, _ []string) error { return nil }
func (b *mockBox) Wait() (int, error)                                              { return 0, nil }
func (b *mockBox) Signal(_ os.Signal) error                                        { return nil }
func (b *mockBox) PTY() io.ReadWriteCloser                                         { return nil }
func (b *mockBox) Pid() int                                                        { return 0 }
func (b *mockBox) JobHandle() uintptr                                              { return 0 }
func (b *mockBox) TempDir() string                                                 { return "" }
func (b *mockBox) Cleanup() error                                                  { return nil }

// resetRegistry clears the global registry so tests are isolated.
func resetRegistry() {
	mu.Lock()
	defer mu.Unlock()
	backends = make(map[string]Backend)
}

func TestRegisterAndGet(t *testing.T) {
	resetRegistry()

	b := &mockBackend{name: "mock", available: true}
	Register(b)

	got, err := Get("mock")
	if err != nil {
		t.Fatalf("Get(%q) error: %v", "mock", err)
	}
	if got.Name() != "mock" {
		t.Errorf("Name(): got %q, want %q", got.Name(), "mock")
	}
}

func TestGetUnknown(t *testing.T) {
	resetRegistry()

	_, err := Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown backend, got nil")
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	resetRegistry()

	Register(&mockBackend{name: "dup"})

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on duplicate registration, got none")
		}
	}()
	Register(&mockBackend{name: "dup"})
}

func TestBackendCreate(t *testing.T) {
	resetRegistry()

	Register(&mockBackend{name: "create-test", available: true})
	b, err := Get("create-test")
	if err != nil {
		t.Fatal(err)
	}

	box, err := b.Create(context.Background(), nil, CreateOpts{})
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	if box == nil {
		t.Fatal("Create() returned nil Box")
	}
}
