// SPDX-License-Identifier: MIT

//go:build windows

package daemon

import (
	"github.com/sungurerdim/dizgin/internal/log"
	"github.com/sungurerdim/dizgin/internal/netfilter"
)

// handlePlatformMessage routes Windows-specific IPC message types.
// Returns (true, resp) when the message was handled, (false, Message{}) otherwise.
func (s *Server) handlePlatformMessage(c *conn, msg Message) (handled bool) {
	switch msg.Type {
	case TypeWFPApply:
		s.handleWFPApply(c, msg)
		return true
	case TypeWFPRevoke:
		s.handleWFPRevoke(c, msg)
		return true
	}
	return false
}

// handleWFPApply installs the user-mode WFP allowlist for a session on
// behalf of a (non-elevated) dizgin client. The daemon is the elevated
// process that holds FWPM_ACTRL_ADD, so the filter add must happen here.
// Single-shot: respond with the summary (or error) and close.
func (s *Server) handleWFPApply(c *conn, msg Message) {
	summary, err := netfilter.Apply(msg.ID, msg.Path, msg.Args)
	var resp Message
	if err != nil {
		resp = Message{Type: TypeStatus, Error: err.Error()}
	} else {
		resp = Message{Type: TypeStatus, Status: summary}
	}
	if sendErr := c.send(resp); sendErr != nil {
		log.Debug("send wfp_apply response: %v", sendErr)
	}
}

// handleWFPRevoke tears down a session's WFP filters. Idempotent on the
// netfilter side (unknown session → no-op).
func (s *Server) handleWFPRevoke(c *conn, msg Message) {
	var resp Message
	if err := netfilter.Revoke(msg.ID); err != nil {
		resp = Message{Type: TypeStatus, Error: err.Error()}
	} else {
		resp = Message{Type: TypeStatus, Status: "ok"}
	}
	if sendErr := c.send(resp); sendErr != nil {
		log.Debug("send wfp_revoke response: %v", sendErr)
	}
}
