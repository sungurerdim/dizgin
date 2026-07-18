// SPDX-License-Identifier: MIT

package daemon

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestMetricsRenderer_EmptyServer asserts the renderer emits the
// baseline metric set (daemon uptime + zero-sample sessions gauge)
// even with no registered sessions. A scraper plotting "active
// sessions over time" should see a zero, not a missing series.
func TestMetricsRenderer_EmptyServer(t *testing.T) {
	srv := NewServer()
	// Skip srv.Close() — it nil-derefs without a prior Listen() call,
	// and the test never opens a listener.

	startedAt := time.Now().Add(-90 * time.Second)
	r := NewMetricsRenderer(srv, startedAt)

	var buf bytes.Buffer
	if err := r.Render(&buf); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()

	mustContain(t, out, "# HELP dizgin_daemon_uptime_seconds")
	mustContain(t, out, "# TYPE dizgin_daemon_uptime_seconds gauge")
	mustContain(t, out, "# HELP dizgin_sessions")
	mustContain(t, out, "# TYPE dizgin_sessions gauge")

	// uptime should be in the 80-100 s window (we used -90 s above)
	upRE := regexp.MustCompile(`(?m)^dizgin_daemon_uptime_seconds (\d+\.\d+)$`)
	m := upRE.FindStringSubmatch(out)
	if len(m) < 2 {
		t.Fatalf("dizgin_daemon_uptime_seconds sample not found in:\n%s", out)
	}

	// zero-sample placeholder for empty session set
	mustContain(t, out, `dizgin_sessions{tool="",status=""} 0`)
}

// TestMetricsRenderer_WithSession registers an instance via the
// server's registry and verifies the per-session series + aggregate
// counter both fire.
func TestMetricsRenderer_WithSession(t *testing.T) {
	srv := NewServer()
	// Skip srv.Close() — it nil-derefs without a prior Listen() call,
	// and the test never opens a listener.

	srv.registry.Register(&Instance{
		InstanceData: InstanceData{
			ID:            "test-session-1",
			Tool:          "claude",
			Workdir:       `C:\work`,
			Backend:       "restricted",
			Status:        StatusRunning,
			MemoryBytes:   42 * 1024 * 1024,
			CPUPercent:    12.5,
			UptimeSeconds: 120,
		},
	})

	r := NewMetricsRenderer(srv, time.Now())
	var buf bytes.Buffer
	if err := r.Render(&buf); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()

	// Aggregate: one session, tool=claude, status=running (the
	// default Upsert path sets StatusRunning).
	mustContain(t, out, `dizgin_sessions{tool="claude",status="running"} 1`)

	// Per-session memory/cpu/uptime: at least the metric headers fire
	// and the labels contain the session id + tool.
	mustContain(t, out, `dizgin_session_memory_bytes{id="test-session-1",tool="claude"}`)
	mustContain(t, out, `dizgin_session_cpu_percent{id="test-session-1",tool="claude"}`)
	mustContain(t, out, `dizgin_session_uptime_seconds{id="test-session-1",tool="claude"}`)
}

// TestEscapeLabelValue ensures the per-spec escape characters
// (backslash, double-quote, newline) all round-trip into the
// expected Prometheus byte sequence; ordinary identifiers pass
// through unchanged.
func TestEscapeLabelValue(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"claude", "claude"},
		{"with space", "with space"},
		{`back\slash`, `back\\slash`},
		{`with"quote`, `with\"quote`},
		{"new\nline", `new\nline`},
		{`a\"b`, `a\\\"b`},
	}
	for _, c := range cases {
		got := escapeLabelValue(c.in)
		if got != c.want {
			t.Errorf("escapeLabelValue(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("expected output to contain %q, got:\n%s", needle, haystack)
	}
}
