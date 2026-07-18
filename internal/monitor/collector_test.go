// SPDX-License-Identifier: MIT

package monitor

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCollectBasic_SelfProcess(t *testing.T) {
	m, err := Collect(CollectOpts{
		PID:       os.Getpid(),
		Level:     LevelBasic,
		StartTime: time.Now().Add(-5 * time.Second),
	})
	if err != nil {
		t.Fatalf("Collect basic: %v", err)
	}
	if m.MemoryBytes == 0 {
		t.Error("MemoryBytes should be > 0 for the current process")
	}
	if m.PIDs == 0 {
		t.Error("PIDs should be >= 1")
	}
	// Basic level should not populate detailed/full fields.
	if m.Uptime != 0 {
		t.Errorf("Uptime should be 0 at basic level, got %v", m.Uptime)
	}
}

func TestCollectDetailed_SelfProcess(t *testing.T) {
	tmpDir := t.TempDir()
	// Write a small file so DiskUsageBytes > 0.
	if err := os.WriteFile(filepath.Join(tmpDir, "test.dat"), make([]byte, 1024), 0600); err != nil {
		t.Fatal(err)
	}

	start := time.Now().Add(-10 * time.Second)
	m, err := Collect(CollectOpts{
		PID:       os.Getpid(),
		Level:     LevelDetailed,
		TempDir:   tmpDir,
		StartTime: start,
	})
	if err != nil {
		t.Fatalf("Collect detailed: %v", err)
	}
	if m.MemoryBytes == 0 {
		t.Error("MemoryBytes should be > 0")
	}
	if m.DiskUsageBytes < 1024 {
		t.Errorf("DiskUsageBytes should be >= 1024, got %d", m.DiskUsageBytes)
	}
	if m.Uptime < 9*time.Second {
		t.Errorf("Uptime should be ~10s, got %v", m.Uptime)
	}
}

func TestCollectFull_SelfProcess(t *testing.T) {
	m, err := Collect(CollectOpts{
		PID:       os.Getpid(),
		Level:     LevelFull,
		StartTime: time.Now(),
	})
	if err != nil {
		t.Fatalf("Collect full: %v", err)
	}
	if m.MemoryBytes == 0 {
		t.Error("MemoryBytes should be > 0")
	}
	// Thread count may be 0 on some Windows configurations where the API
	// does not expose this metric. Log it as informational rather than failing.
	if m.ThreadCount == 0 {
		t.Logf("ThreadCount = %d (may be 0 on some platforms)", m.ThreadCount)
	}
	// ChildPIDs can be nil (test process has no children), that's OK.
}

func TestDirSize_Empty(t *testing.T) {
	dir := t.TempDir()
	if size := dirSize(dir); size != 0 {
		t.Errorf("empty dir size: want 0, got %d", size)
	}
}

func TestDirSize_WithFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), make([]byte, 500), 0600)  //nolint:errcheck
	os.WriteFile(filepath.Join(dir, "b.txt"), make([]byte, 1500), 0600) //nolint:errcheck

	size := dirSize(dir)
	if size < 2000 {
		t.Errorf("dir size: want >= 2000, got %d", size)
	}
}

// ── MetricsLevel ────────────────────────────────────────────────────────────

func TestCollectMetricsLevel_BasicOmitsDetailed(t *testing.T) {
	start := time.Now().Add(-5 * time.Second)
	m, err := Collect(CollectOpts{
		PID:       os.Getpid(),
		Level:     LevelBasic,
		TempDir:   t.TempDir(),
		StartTime: start,
	})
	if err != nil {
		t.Fatalf("Collect basic: %v", err)
	}
	// Basic level should NOT populate Uptime, DiskUsageBytes, or ChildPIDs.
	if m.Uptime != 0 {
		t.Errorf("basic level: Uptime should be 0, got %v", m.Uptime)
	}
	if m.DiskUsageBytes != 0 {
		t.Errorf("basic level: DiskUsageBytes should be 0, got %d", m.DiskUsageBytes)
	}
	if m.ChildPIDs != nil {
		t.Errorf("basic level: ChildPIDs should be nil, got %v", m.ChildPIDs)
	}
	if m.HandleCount != 0 {
		t.Errorf("basic level: HandleCount should be 0, got %d", m.HandleCount)
	}
}

func TestCollectMetricsLevel_DetailedOmitsFull(t *testing.T) {
	start := time.Now().Add(-3 * time.Second)
	m, err := Collect(CollectOpts{
		PID:       os.Getpid(),
		Level:     LevelDetailed,
		StartTime: start,
	})
	if err != nil {
		t.Fatalf("Collect detailed: %v", err)
	}
	// Detailed level should populate Uptime but NOT ChildPIDs or HandleCount.
	if m.Uptime < 2*time.Second {
		t.Errorf("detailed level: Uptime should be ~3s, got %v", m.Uptime)
	}
	if m.ChildPIDs != nil {
		t.Errorf("detailed level: ChildPIDs should be nil, got %v", m.ChildPIDs)
	}
	if m.HandleCount != 0 {
		t.Errorf("detailed level: HandleCount should be 0, got %d", m.HandleCount)
	}
}

func TestCollectMetricsLevel_FullPopulatesAll(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "x.dat"), make([]byte, 256), 0600) //nolint:errcheck

	start := time.Now().Add(-2 * time.Second)
	m, err := Collect(CollectOpts{
		PID:       os.Getpid(),
		Level:     LevelFull,
		TempDir:   tmpDir,
		StartTime: start,
	})
	if err != nil {
		t.Fatalf("Collect full: %v", err)
	}
	// Full level should populate memory and uptime.
	if m.MemoryBytes == 0 {
		t.Error("full level: MemoryBytes should be > 0")
	}
	if m.Uptime < 1*time.Second {
		t.Errorf("full level: Uptime should be ~2s, got %v", m.Uptime)
	}
	// HandleCount or ThreadCount may be 0 on some platforms; log info.
	t.Logf("full level: HandleCount=%d ThreadCount=%d ChildPIDs=%d",
		m.HandleCount, m.ThreadCount, len(m.ChildPIDs))
}

// ── CollectOpts variations ──────────────────────────────────────────────────

func TestNewCollector_ZeroPID(t *testing.T) {
	// PID 0 is the System Idle Process on Windows; Collect should not panic.
	_, err := Collect(CollectOpts{
		PID:       0,
		Level:     LevelBasic,
		StartTime: time.Now(),
	})
	// Error is acceptable; panic is not.
	_ = err
}

func TestNewCollector_NoTempDir(t *testing.T) {
	m, err := Collect(CollectOpts{
		PID:       os.Getpid(),
		Level:     LevelDetailed,
		StartTime: time.Now(),
	})
	if err != nil {
		t.Fatalf("Collect without TempDir: %v", err)
	}
	// Without TempDir, DiskUsageBytes should remain 0.
	if m.DiskUsageBytes != 0 {
		t.Errorf("no TempDir: DiskUsageBytes should be 0, got %d", m.DiskUsageBytes)
	}
}

func TestNewCollector_ZeroStartTime(t *testing.T) {
	m, err := Collect(CollectOpts{
		PID:   os.Getpid(),
		Level: LevelDetailed,
	})
	if err != nil {
		t.Fatalf("Collect with zero StartTime: %v", err)
	}
	// With zero StartTime, Uptime should remain 0.
	if m.Uptime != 0 {
		t.Errorf("zero StartTime: Uptime should be 0, got %v", m.Uptime)
	}
}

// ── Start/Stop (sequential collect calls) ───────────────────────────────────

func TestCollectorStartStop_NoPanic(t *testing.T) {
	opts := CollectOpts{
		PID:       os.Getpid(),
		Level:     LevelBasic,
		StartTime: time.Now(),
	}
	// Simulate a collector start/stop cycle: multiple sequential Collect calls
	// should not panic or return errors.
	for i := 0; i < 3; i++ {
		m, err := Collect(opts)
		if err != nil {
			t.Fatalf("Collect iteration %d: %v", i, err)
		}
		if m.MemoryBytes == 0 {
			t.Errorf("iteration %d: MemoryBytes should be > 0", i)
		}
	}
}

func TestCollectorStartStop_LevelSwitch(t *testing.T) {
	// Switching levels between calls should work without issues.
	levels := []Level{LevelBasic, LevelDetailed, LevelFull, LevelBasic}
	for _, level := range levels {
		_, err := Collect(CollectOpts{
			PID:       os.Getpid(),
			Level:     level,
			StartTime: time.Now(),
		})
		if err != nil {
			t.Fatalf("Collect at level %q: %v", level, err)
		}
	}
}

// ── Level constants ─────────────────────────────────────────────────────────

func TestLevelConstants(t *testing.T) {
	if LevelBasic != "basic" {
		t.Errorf("LevelBasic: got %q, want %q", LevelBasic, "basic")
	}
	if LevelDetailed != "detailed" {
		t.Errorf("LevelDetailed: got %q, want %q", LevelDetailed, "detailed")
	}
	if LevelFull != "full" {
		t.Errorf("LevelFull: got %q, want %q", LevelFull, "full")
	}
}

// ── DirSize with subdirectories ─────────────────────────────────────────────

func TestDirSize_WithSubdirs(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	os.Mkdir(sub, 0700)                                                    //nolint:errcheck
	os.WriteFile(filepath.Join(dir, "root.txt"), make([]byte, 100), 0600)  //nolint:errcheck
	os.WriteFile(filepath.Join(sub, "child.txt"), make([]byte, 200), 0600) //nolint:errcheck

	size := dirSize(dir)
	if size < 300 {
		t.Errorf("dir size with subdirs: want >= 300, got %d", size)
	}
}

func BenchmarkCollectBasic(b *testing.B) {
	opts := CollectOpts{
		PID:       os.Getpid(),
		Level:     LevelBasic,
		StartTime: time.Now(),
	}
	for b.Loop() {
		Collect(opts) //nolint:errcheck
	}
}

func BenchmarkCollectDetailed(b *testing.B) {
	dir := b.TempDir()
	opts := CollectOpts{
		PID:       os.Getpid(),
		Level:     LevelDetailed,
		TempDir:   dir,
		StartTime: time.Now(),
	}
	for b.Loop() {
		Collect(opts) //nolint:errcheck
	}
}

func BenchmarkCollectFull(b *testing.B) {
	opts := CollectOpts{
		PID:       os.Getpid(),
		Level:     LevelFull,
		StartTime: time.Now(),
	}
	for b.Loop() {
		Collect(opts) //nolint:errcheck
	}
}
