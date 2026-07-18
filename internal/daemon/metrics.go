// SPDX-License-Identifier: MIT

package daemon

import (
	"fmt"
	"io"
	"time"
)

// MetricsRenderer writes Prometheus text-format metrics from a Server
// snapshot. The renderer holds a daemon-start timestamp so uptime
// samples stay monotonic across scrapes regardless of when the renderer
// itself was constructed.
//
// Format: Prometheus exposition v0.0.4 — HELP / TYPE comments + one
// sample line per series. Label values are escaped per spec (\\, \",
// \n). The set of metrics is intentionally small:
//
//	dizgin_daemon_uptime_seconds   gauge
//	dizgin_sessions                gauge {tool, status}
//	dizgin_session_memory_bytes    gauge {id, tool}
//	dizgin_session_cpu_percent     gauge {id, tool}
//	dizgin_session_uptime_seconds  gauge {id, tool}
//
// "Active" means any session the daemon has registered and has not
// pruned by heartbeat timeout. A session in StatusDead is included
// (with its terminal stats) until the orphan sweeper retires it.
type MetricsRenderer struct {
	srv       *Server
	startedAt time.Time
}

// NewMetricsRenderer captures startedAt so uptime samples are stable
// across renders. srv is the live daemon — we read instance state on
// each Render call so scrapers always see fresh data.
func NewMetricsRenderer(srv *Server, startedAt time.Time) *MetricsRenderer {
	return &MetricsRenderer{srv: srv, startedAt: startedAt}
}

// Render writes a Prometheus text-format snapshot to w. Returns any
// I/O error from the underlying writer (a partial render is the
// caller's problem — the HTTP handler closes the response either way).
func (m *MetricsRenderer) Render(w io.Writer) error {
	uptimeSec := time.Since(m.startedAt).Seconds()
	if _, err := fmt.Fprintln(w, "# HELP dizgin_daemon_uptime_seconds Seconds since the dizgind daemon started."); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "# TYPE dizgin_daemon_uptime_seconds gauge"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "dizgin_daemon_uptime_seconds %.3f\n", uptimeSec); err != nil {
		return err
	}

	infos := m.srv.Infos()

	if _, err := fmt.Fprintln(w, "# HELP dizgin_sessions Active sandbox sessions, grouped by tool and lifecycle status."); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "# TYPE dizgin_sessions gauge"); err != nil {
		return err
	}
	counts := make(map[[2]string]int)
	for _, inst := range infos {
		key := [2]string{inst.Tool, string(inst.Status)}
		counts[key]++
	}
	if len(counts) == 0 {
		// Emit a zero sample so scrapers can plot "no active sessions"
		// without a missing-metric gap. Empty labels are valid per spec.
		if _, err := fmt.Fprintln(w, `dizgin_sessions{tool="",status=""} 0`); err != nil {
			return err
		}
	} else {
		for k, v := range counts {
			if _, err := fmt.Fprintf(w, "dizgin_sessions{tool=\"%s\",status=\"%s\"} %d\n",
				escapeLabelValue(k[0]), escapeLabelValue(k[1]), v); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintln(w, "# HELP dizgin_session_memory_bytes Memory usage per active sandbox session."); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "# TYPE dizgin_session_memory_bytes gauge"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "# HELP dizgin_session_cpu_percent CPU usage percent per active sandbox session."); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "# TYPE dizgin_session_cpu_percent gauge"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "# HELP dizgin_session_uptime_seconds Uptime per active sandbox session."); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "# TYPE dizgin_session_uptime_seconds gauge"); err != nil {
		return err
	}
	for _, inst := range infos {
		labels := fmt.Sprintf("{id=\"%s\",tool=\"%s\"}",
			escapeLabelValue(inst.ID), escapeLabelValue(inst.Tool))
		if _, err := fmt.Fprintf(w, "dizgin_session_memory_bytes%s %d\n", labels, inst.MemoryBytes); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "dizgin_session_cpu_percent%s %.3f\n", labels, inst.CPUPercent); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "dizgin_session_uptime_seconds%s %d\n", labels, inst.UptimeSeconds); err != nil {
			return err
		}
	}
	return nil
}

// escapeLabelValue applies Prometheus label-value escaping. Per spec
// the only required escapes inside a quoted label value are backslash,
// double-quote, and newline. Tab and other control characters are
// allowed verbatim but rare in our identifiers.
func escapeLabelValue(s string) string {
	if s == "" {
		return ""
	}
	// Quick path: most labels (tool name, status enum, session id)
	// contain none of the escape-target characters. Scan first to
	// avoid an allocation for the common case.
	if !needsEscape(s) {
		return s
	}
	out := make([]byte, 0, len(s)+4)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			out = append(out, '\\', '\\')
		case '"':
			out = append(out, '\\', '"')
		case '\n':
			out = append(out, '\\', 'n')
		default:
			out = append(out, s[i])
		}
	}
	return string(out)
}

func needsEscape(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\', '"', '\n':
			return true
		}
	}
	return false
}
