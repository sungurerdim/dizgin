// SPDX-License-Identifier: MIT

// Package audit provides a structured JSON-L audit log for dizgin sessions.
// The log records session lifecycle events, credential injections, network
// blocks, and process signals.
//
// Configuration:
//
//	audit:
//	  enabled: false       # opt-in (default off)
//	  max_size_mb: 10      # rotate / discard when file exceeds this limit
//
// Log location:
//
//	Unix:    ~/.local/share/dizgin/audit.jsonl
//	Windows: %LOCALAPPDATA%\dizgin.audit.jsonl
//
// Enable via environment variable: DIZGIN_AUDIT=true
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// Event types written to the audit log.
const (
	EventSessionStart     = "session.start"
	EventSessionStop      = "session.stop"
	EventCredentialInject = "credential.inject" //nolint:gosec // G101 false positive: audit event name, not a credential
	EventNetworkBlocked   = "network.blocked"
	EventNetworkEnforce   = "network.enforce"
	EventProcessSignal    = "process.signal"
)

// entry is a single audit log record.
type entry struct {
	Time    string `json:"time"`
	Event   string `json:"event"`
	Session string `json:"session,omitempty"`
	Tool    string `json:"tool,omitempty"`
	Workdir string `json:"workdir,omitempty"`
	Backend string `json:"backend,omitempty"`
	Key     string `json:"key,omitempty"`
	Source  string `json:"source,omitempty"`
	Host    string `json:"host,omitempty"`
	Signal  string `json:"signal,omitempty"`
	Msg     string `json:"msg,omitempty"`
	Code    int    `json:"code,omitempty"`
}

// Logger writes structured audit events to a JSON-L file.
type Logger struct {
	file        *os.File
	maxSize     int64
	writeErrors int
	mu          sync.Mutex
	enabled     bool
}

var defaultLogger *Logger
var initOnce sync.Once

// Default returns the process-wide audit logger.
// It is initialised lazily from environment/config on first call.
func Default() *Logger {
	initOnce.Do(func() {
		defaultLogger = &Logger{enabled: false}
	})
	return defaultLogger
}

// Configure enables or reconfigures the default logger.
// Call once during startup with values from config.
func Configure(enabled bool, maxSizeMB int) error {
	l := Default()
	l.mu.Lock()
	defer l.mu.Unlock()

	if !enabled {
		if l.file != nil {
			_ = l.file.Close()
			l.file = nil
		}
		l.enabled = false
		return nil
	}

	logPath, err := logFilePath()
	if err != nil {
		return fmt.Errorf("audit: log path: %w", err)
	}
	if mkErr := os.MkdirAll(filepath.Dir(logPath), 0700); mkErr != nil {
		return fmt.Errorf("audit: mkdir: %w", mkErr)
	}

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("audit: open %q: %w", logPath, err)
	}

	if l.file != nil {
		_ = l.file.Close()
	}
	l.file = f
	l.enabled = true
	if maxSizeMB > 0 {
		l.maxSize = int64(maxSizeMB) * 1024 * 1024
	}
	return nil
}

// Log writes a single audit event.
func (l *Logger) Log(event string, fields entry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.enabled || l.file == nil {
		return
	}

	// Rotate if file exceeds the size limit.
	if l.maxSize > 0 {
		if info, err := l.file.Stat(); err == nil && info.Size() >= l.maxSize {
			_ = l.file.Close()
			// Truncate: reopen with O_TRUNC to keep path but clear old data.
			if f, err := os.OpenFile(l.file.Name(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600); err == nil {
				l.file = f
			} else {
				l.enabled = false
				return
			}
		}
	}

	fields.Time = time.Now().UTC().Format(time.RFC3339)
	fields.Event = event
	data, _ := json.Marshal(fields)
	data = append(data, '\n')
	if _, err := l.file.Write(data); err != nil {
		l.writeErrors++
	}
}

// WriteErrors returns the number of failed write operations since the logger
// was configured. Safe to call concurrently.
func (l *Logger) WriteErrors() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.writeErrors
}

// Close flushes and closes the audit log file. If write errors occurred,
// a warning is printed to stderr.
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.writeErrors > 0 {
		fmt.Fprintf(os.Stderr, brand.Name+": audit: %d write error(s) occurred during session\n", l.writeErrors)
	}
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
	l.enabled = false
}

// ── Convenience methods on Default ───────────────────────────────────────────

// SessionStart logs the start of a sandbox session.
func SessionStart(sessionID, tool, workdir, backend string) {
	Default().Log(EventSessionStart, entry{
		Session: sessionID,
		Tool:    tool,
		Workdir: workdir,
		Backend: backend,
	})
}

// SessionStop logs the end of a sandbox session with its exit code.
func SessionStop(sessionID string, exitCode int) {
	Default().Log(EventSessionStop, entry{
		Session: sessionID,
		Code:    exitCode,
	})
}

// CredentialInject logs that a credential was injected into the sandbox.
// The value is never logged — only the key and source.
func CredentialInject(sessionID, key, source string) {
	Default().Log(EventCredentialInject, entry{
		Session: sessionID,
		Key:     key,
		Source:  source,
	})
}

// NetworkBlocked logs a blocked network destination.
func NetworkBlocked(sessionID, host string) {
	Default().Log(EventNetworkBlocked, entry{
		Session: sessionID,
		Host:    host,
	})
}

// NetworkEnforce logs the outcome of a WFP network-allowlist apply
// attempt: ok=true with a summary (permit/skip counts) on success, or
// ok=false with the degrade reason when the session fell back to
// advisory (daemon down, non-Windows, WFP error).
func NetworkEnforce(sessionID string, ok bool, detail string) {
	status := "advisory"
	if ok {
		status = "enforced"
	}
	Default().Log(EventNetworkEnforce, entry{
		Session: sessionID,
		Source:  status,
		Msg:     detail,
	})
}

// ProcessSignal logs that a signal was delivered to the sandbox process.
func ProcessSignal(sessionID, signal string) {
	Default().Log(EventProcessSignal, entry{
		Session: sessionID,
		Signal:  signal,
	})
}
