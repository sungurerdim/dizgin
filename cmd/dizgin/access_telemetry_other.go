// SPDX-License-Identifier: MIT

//go:build !windows

package main

// newAccessTelemetry returns the access telemetry observer for
// bubblewrap / seatbelt hosts. Behaviour is identical to the Windows
// build today — Unix tools emit the same ENOENT / "no such file" shape
// and the path extractor handles both. The split exists so the Windows
// feature can diverge (cmd.exe-specific patterns, ANSI filtering) in
// future milestones without a platform gate in session.go.
func newAccessTelemetry() *accessTelemetry { return newAccessTelemetryCore() }
