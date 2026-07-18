// SPDX-License-Identifier: MIT

// Package daemon implements the dizgind IPC server and client.
// The server runs inside dizgind; the client runs inside dizgin.
// Communication uses JSON messages over a named pipe (Windows)
// or a unix domain socket (Linux/macOS).
//
// Implemented in T19+.
package daemon
