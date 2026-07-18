// SPDX-License-Identifier: MIT

package daemon

import (
	"fmt"
	"net"
	"time"
)

// Dial connects to a running dizgind daemon using the platform transport.
// Returns an error if the daemon is not running or unreachable.
func Dial(timeout time.Duration) (net.Conn, error) {
	nc, err := dial(timeout)
	if err != nil {
		return nil, fmt.Errorf("daemon: not running or unreachable: %w", err)
	}
	return nc, nil
}

// daemonCall dials the daemon socket, sends a request message, and returns
// the decoded response. The connection is closed before returning.
func daemonCall(msg Message) (*Message, error) {
	conn, err := dial(2 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("daemon: not running or unreachable: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	if err := NewEncoder(conn).Encode(msg); err != nil {
		return nil, fmt.Errorf("send %s: %w", msg.Type, err)
	}

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var resp Message
	if err := NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("receive %s response: %w", msg.Type, err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("daemon: %s", resp.Error)
	}
	return &resp, nil
}

// QueryStatus connects to the daemon, requests a status snapshot, and returns
// the list of active instances. The connection is closed after the response.
func QueryStatus() ([]InstanceInfo, error) {
	resp, err := daemonCall(Message{Type: TypeQueryStatus})
	if err != nil {
		return nil, err
	}
	return resp.Instances, nil
}

// SendRemoteCommand sends a control action (suspend/resume/kill/restart) to a session
// via the daemon's admin IPC. Used by the remote TUI.
func SendRemoteCommand(sessionID string, action CommandAction) error {
	_, err := daemonCall(Message{
		Type:   TypeRemoteCommand,
		ID:     sessionID,
		Action: action,
	})
	return err
}

// LaunchRemoteSession requests the daemon to spawn a new sandboxed session.
func LaunchRemoteSession(tool, workdir string, args []string) error {
	_, err := daemonCall(Message{
		Type:    TypeLaunch,
		Tool:    tool,
		Workdir: workdir,
		Args:    args,
	})
	return err
}

// ApplyNetworkFilter asks the (elevated) daemon to install the user-mode
// WFP allowlist for a session, scoped to the appPath binary. Returns the
// daemon's summary line on success or an error (daemon down, WFP failure,
// non-Windows). The caller degrades to advisory on error.
func ApplyNetworkFilter(sessionID, appPath string, allowlist []string) (string, error) {
	resp, err := daemonCall(Message{
		Type: TypeWFPApply,
		ID:   sessionID,
		Path: appPath,
		Args: allowlist,
	})
	if err != nil {
		return "", err
	}
	return resp.Status, nil
}

// RevokeNetworkFilter asks the daemon to tear down a session's WFP
// filters. Best-effort: revoking an unknown session is a daemon-side
// no-op.
func RevokeNetworkFilter(sessionID string) error {
	_, err := daemonCall(Message{Type: TypeWFPRevoke, ID: sessionID})
	return err
}

// IsDaemonRunning checks if the dizgind daemon is reachable.
func IsDaemonRunning() bool {
	conn, err := dial(1 * time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// Shutdown connects to the daemon and requests graceful shutdown.
// The connection is closed after the acknowledgement is received.
func Shutdown() error {
	// Best-effort: the daemon may close the connection before responding,
	// so we ignore any receive errors.
	_, _ = daemonCall(Message{Type: TypeShutdown})
	return nil
}
