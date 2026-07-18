// SPDX-License-Identifier: MIT

//go:build !windows

package daemon

// handlePlatformMessage is a no-op on non-Windows platforms.
// Windows-specific message types (TypeWFPApply, TypeWFPRevoke) are not
// dispatched on this platform; handleConn falls through to the default case.
func (s *Server) handlePlatformMessage(_ *conn, _ Message) (handled bool) {
	return false
}
