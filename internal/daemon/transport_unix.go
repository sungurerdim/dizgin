// SPDX-License-Identifier: MIT

//go:build !windows

package daemon

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// socketDir returns the directory that holds the unix socket.
// When XDG_RUNTIME_DIR is set it is already a private per-user directory
// (mode 0700 by the desktop session manager). On the fallback path we use a
// deterministic per-user subdirectory under os.TempDir(); listen() creates
// it with mode 0700 so the socket lives in a directory only the owner can
// access, eliminating the os.Remove-then-Listen TOCTOU window that would
// exist if the socket were placed directly in the shared /tmp.
func socketDir() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return d
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("dizgind-%d", os.Getuid()))
}

// socketPath returns the unix socket path for the daemon.
func socketPath() string {
	return filepath.Join(socketDir(), brand.SocketFile)
}

// listen creates a unix domain socket listener with 0600 permissions.
// On the XDG_RUNTIME_DIR path the directory is already private; we just
// remove any stale socket before binding. On the fallback path we create
// the per-user socket directory (0700) first so the socket is protected
// by directory permissions and no TOCTOU window exists.
func listen() (net.Listener, error) {
	dir := socketDir()
	path := filepath.Join(dir, brand.SocketFile)

	if os.Getenv("XDG_RUNTIME_DIR") != "" {
		// Safe path: XDG_RUNTIME_DIR is already a private per-user directory.
		// Remove stale socket if present.
		os.Remove(path) //nolint:errcheck
	} else {
		// Fallback: ensure the per-user directory exists with mode 0700.
		// MkdirAll is idempotent; if the dir already exists its permissions
		// are unchanged (Chmod below enforces 0700 regardless).
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("transport: mkdir %q: %w", dir, err)
		}
		if err := os.Chmod(dir, 0700); err != nil {
			return nil, fmt.Errorf("transport: chmod dir %q: %w", dir, err)
		}
		// Remove stale socket if present (safe inside our own private dir).
		os.Remove(path) //nolint:errcheck
	}

	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("transport: listen unix %q: %w", path, err)
	}
	// Set permissions to 0600 so only the owner can connect.
	if err = os.Chmod(path, 0600); err != nil {
		l.Close() //nolint:errcheck
		return nil, fmt.Errorf("transport: chmod %q: %w", path, err)
	}
	return l, nil
}

// dial connects to the daemon unix socket.
func dial(timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", socketPath(), timeout)
}
