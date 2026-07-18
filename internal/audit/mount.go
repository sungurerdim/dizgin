// SPDX-License-Identifier: MIT

// Package audit — per-session mount-decision audit log.
//
// Writes one JSONL line per stamp decision (R1-A / R1-B / R1-C / skip /
// deny) to ~/.dizgin/audit/<session-id>.jsonl. The per-session file makes
// post-mortem of an R1 violation cheap: tail the file, see exactly
// which paths the backend stamped, with what category, and which were
// dropped.
//
// The function is best-effort — audit-log failures must never abort
// session creation. Disable via DIZGIN_AUDIT_MOUNTS=0.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// MountDecision is one stamp/skip decision emitted by the restricted
// backend's mount classifier (or its Seatbelt / bwrap mirror on
// macOS / Linux). The shape is intentionally flat so a jq one-liner
// can pull the field of interest.
type MountDecision struct {
	Time     string `json:"time"`
	Session  string `json:"session"`
	Category string `json:"category"`
	Host     string `json:"host"`
	ReadOnly bool   `json:"read_only"`
	Granted  bool   `json:"granted"`
	Skipped  bool   `json:"skipped,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Err      string `json:"err,omitempty"`
}

var mountAuditMu sync.Mutex

// LogMountDecision appends one JSONL record describing how the
// classifier handled mount <host>. Failures are silent; the function
// never returns an error so callers can chain it unconditionally inside
// hot loops without ballooning their error-handling surface.
func LogMountDecision(sessionID string, d MountDecision) {
	if os.Getenv(brand.Env("AUDIT_MOUNTS")) == "0" {
		return
	}
	if sessionID == "" {
		return
	}
	d.Time = time.Now().UTC().Format(time.RFC3339Nano)
	d.Session = sessionID

	dir, err := mountAuditDir()
	if err != nil {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	path := filepath.Join(dir, sessionID+".jsonl")

	mountAuditMu.Lock()
	defer mountAuditMu.Unlock()

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close() //nolint:errcheck

	enc := json.NewEncoder(f)
	_ = enc.Encode(d)
}

// mountAuditDir returns ~/.dizgin/audit. Centralised so the path is one
// SSOT shared by writer and any future dizgin doctor consumer.
func mountAuditDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, brand.DotDir, "audit"), nil
}
