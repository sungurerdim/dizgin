// SPDX-License-Identifier: MIT

// Package daemon implements the dizgind IPC server and client.
package daemon

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// MessageType identifies the kind of IPC message.
type MessageType string

const (
	// TypeRegister is sent by dizgin to announce a new session.
	TypeRegister MessageType = "register"
	// TypeHeartbeat is sent periodically by dizgin with status updates.
	TypeHeartbeat MessageType = "heartbeat"
	// TypeDeregister is sent by dizgin when the session ends.
	TypeDeregister MessageType = "deregister"
	// TypeCommand is sent by dizgind to control a session.
	TypeCommand MessageType = "command"
	// TypeStatus is sent by dizgind in response to a status query.
	TypeStatus MessageType = "status"
	// TypeQueryStatus is sent by an admin client to request a status snapshot.
	TypeQueryStatus MessageType = "query_status"
	// TypeShutdown is sent by an admin client to request graceful daemon shutdown.
	TypeShutdown MessageType = "shutdown"
	// TypeWFPApply is sent by dizgin to ask the elevated daemon to install
	// the user-mode WFP network allowlist for a session. ID = sessionID,
	// Path = tool binary (app-id scope), Args = raw allowlist entries.
	TypeWFPApply MessageType = "wfp_apply"
	// TypeWFPRevoke is sent by dizgin at session end to tear down the WFP
	// filters. ID = sessionID.
	TypeWFPRevoke MessageType = "wfp_revoke"
)

// CommandAction is the action field of a TypeCommand message.
type CommandAction string

const (
	ActionSuspend CommandAction = "suspend"
	ActionResume  CommandAction = "resume"
	ActionKill    CommandAction = "kill"
)

// Message is the canonical IPC message exchanged over the named pipe / unix socket.
// Fields are omitted from JSON when empty to minimise wire size.
//
// Because the IPC is internal and typed (MessageType drives dispatch), a single
// struct covers all message variants. Fields are grouped below by the message
// type(s) that use them. Fields marked [all] appear in most or all types.
// Do NOT add new message types that reuse existing fields with a different
// semantic — add named fields instead to prevent mis-wiring.
//
// [all]            Type, Error (error response for any type)
// [register]       ID, PID, Tool, Workdir, Backend, Args
// [heartbeat]      ID, Status, Snippet, CPU, Memory, PIDs, ChildPIDs,
//
//	IORead, IOWrite, DiskUsage, Uptime, ThreadCount, HandleCount
//
// [deregister]     ID, Exit
// [command]        ID, Action (server → dizgin)
// [query_status]   (no payload fields)
// [status]         Status, Instances, Error (server response)
// [shutdown]       (no payload fields; response: Status="shutting_down")
// [wfp_apply]      ID=sessionID, Path=tool-binary (app-id scope),
//
//	Args=raw allowlist entries (reuses generic fields; see admin.go ApplyNetworkFilter)
//
// [wfp_revoke]     ID=sessionID
type Message struct {
	// [all] Message type discriminator.
	Type MessageType `json:"type"`

	// [register, heartbeat, deregister, command, wfp_apply, wfp_revoke]
	// Session identifier assigned by dizgin at registration time.
	ID string `json:"id,omitempty"`

	// [command] Action to perform on the session.
	Action CommandAction `json:"action,omitempty"`

	// [register] Tool binary name (e.g. "claude", "cursor").
	Tool string `json:"tool,omitempty"`

	// [wfp_apply] Tool binary path for app-id scoping of WFP filters.
	// Not used by any non-WFP message type.
	Path string `json:"path,omitempty"`

	// [register] Sandbox working directory.
	Workdir string `json:"workdir,omitempty"`

	// [register] Backend name (e.g. "restricted", "seatbelt", "bubblewrap").
	Backend string `json:"backend,omitempty"`

	// [heartbeat, status] Human-readable status string ("running", "shutting_down", "ok", …).
	Status string `json:"status,omitempty"`

	// [heartbeat] Last prompt snippet; sanitised by RedactSnippet before transmission.
	Snippet string `json:"last_prompt_snippet,omitempty"`

	// [all error responses] Error message from the server.
	Error string `json:"error,omitempty"`

	// [register, wfp_apply] Extra arguments.
	// TypeRegister: tool argv; TypeWFPApply: raw allowlist entries.
	Args []string `json:"args,omitempty"`

	// [heartbeat] Child process IDs of the sandboxed session.
	ChildPIDs []int `json:"child_pids,omitempty"`

	// [status] Active instance snapshots returned by TypeQueryStatus.
	Instances []InstanceInfo `json:"instances,omitempty"`

	// [register] Caller process ID.
	PID int `json:"pid,omitempty"`

	// [heartbeat] Process count in the session's Job Object / cgroup.
	// Distinct from PID above — "pids" (plural) vs "pid".
	PIDs int `json:"pids,omitempty"`

	// [deregister] Exit code of the sandboxed tool process.
	Exit int `json:"exit_code,omitempty"`

	// [heartbeat] CPU utilisation (0–100 percent).
	CPU float64 `json:"cpu_percent,omitempty"`

	// [heartbeat] Resident memory in bytes.
	Memory uint64 `json:"memory_bytes,omitempty"`

	// [heartbeat] Cumulative bytes read from disk.
	IORead uint64 `json:"io_read_bytes,omitempty"`

	// [heartbeat] Cumulative bytes written to disk.
	IOWrite uint64 `json:"io_write_bytes,omitempty"`

	// [heartbeat] Scratch-directory disk usage in bytes.
	DiskUsage uint64 `json:"disk_usage_bytes,omitempty"`

	// [heartbeat] Session uptime in seconds.
	Uptime int64 `json:"uptime_seconds,omitempty"`

	// [heartbeat] OS thread count for the session.
	ThreadCount int `json:"thread_count,omitempty"`

	// [heartbeat] Open handle count (Windows) or file-descriptor count (unix).
	HandleCount int `json:"handle_count,omitempty"`
}

// InstanceInfo is a JSON-serialisable snapshot of an Instance.
// It avoids embedding sync.Mutex in the wire format.
type InstanceInfo struct {
	ID             string         `json:"id"`
	Tool           string         `json:"tool"`
	Workdir        string         `json:"workdir"`
	Backend        string         `json:"backend"`
	Status         InstanceStatus `json:"status"`
	LastSnippet    string         `json:"last_prompt_snippet,omitempty"`
	Args           []string       `json:"args,omitempty"`
	ChildPIDs      []int          `json:"child_pids,omitempty"`
	PIDs           int            `json:"pids,omitempty"`
	CPUPercent     float64        `json:"cpu_percent,omitempty"`
	MemoryBytes    uint64         `json:"memory_bytes,omitempty"`
	ExitCode       int            `json:"exit_code,omitempty"`
	IOReadBytes    uint64         `json:"io_read_bytes,omitempty"`
	IOWriteBytes   uint64         `json:"io_write_bytes,omitempty"`
	DiskUsageBytes uint64         `json:"disk_usage_bytes,omitempty"`
	UptimeSeconds  int64          `json:"uptime_seconds,omitempty"`
	ThreadCount    int            `json:"thread_count,omitempty"`
	HandleCount    int            `json:"handle_count,omitempty"`
	LastHeartbeat  int64          `json:"last_heartbeat_unix"`
	PID            int            `json:"pid"`
}

// Encoder writes newline-delimited JSON messages to an io.Writer.
type Encoder struct {
	enc *json.Encoder
}

// NewEncoder creates an Encoder that writes to w.
func NewEncoder(w io.Writer) *Encoder {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &Encoder{enc: enc}
}

// Encode marshals msg as a single-line JSON object followed by '\n'.
func (e *Encoder) Encode(msg Message) error {
	if err := e.enc.Encode(msg); err != nil {
		return fmt.Errorf("codec: encode: %w", err)
	}
	return nil
}

// Decoder reads newline-delimited JSON messages from an io.Reader.
type Decoder struct {
	dec *json.Decoder
	lr  *io.LimitedReader
}

// maxMessageSize is the upper bound for a single IPC JSON message (1 MB).
// Messages beyond this size are malformed or malicious.
const maxMessageSize = 1 << 20

// NewDecoder creates a Decoder that reads from r.
// Each message read is limited to maxMessageSize bytes.
func NewDecoder(r io.Reader) *Decoder {
	lr := &io.LimitedReader{R: r, N: maxMessageSize}
	return &Decoder{dec: json.NewDecoder(lr), lr: lr}
}

// Decode reads the next JSON line from the reader and populates msg.
// Returns io.EOF when the connection closes normally.
// Each call resets the per-message byte limit so long-lived connections
// are not affected by the cumulative read count.
func (d *Decoder) Decode(msg *Message) error {
	d.lr.N = maxMessageSize
	if err := d.dec.Decode(msg); err != nil {
		return err // preserves io.EOF
	}
	return nil
}

// secretPattern matches lines that likely contain sensitive credentials.
var secretPattern = regexp.MustCompile(`(?i)(api[_-]?key|token|password|secret|credential|auth)[=:\s]`)

// RedactSnippet sanitises a heartbeat snippet before transmission.
// It truncates to 80 characters and replaces lines matching common secret
// patterns (API key, token, password, etc.) with "[redacted]".
//
// Non-secret prompt text is intentionally visible to same-user clients of
// the dizgind pipe (status/observability feature). This is by design:
// the snippet is observability data scoped to the pipe owner, not a
// secret. The transport layer (named-pipe DACL / 0600 unix socket + SEC-01
// peer-uid check) prevents cross-user exposure. Any future requirement to
// suppress non-secret prompt text entirely should be implemented as an
// explicit opt-in field in the TypeHeartbeat message (e.g. SnippetEnabled)
// rather than silently dropping the field.
func RedactSnippet(s string) string {
	if s == "" {
		return s
	}
	// Redact lines that look like they contain secrets.
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if secretPattern.MatchString(line) {
			out = append(out, "[redacted]")
		} else {
			out = append(out, line)
		}
	}
	result := strings.Join(out, "\n")
	if len(result) > 80 {
		result = result[:80]
	}
	return result
}
