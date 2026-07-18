// SPDX-License-Identifier: MIT

//go:build windows

package main

// newAccessTelemetry returns the Windows-specific access telemetry
// observer. AppContainer-sandboxed tools surface a mix of cmd.exe,
// PowerShell and POSIX-shell error messages, so the full pattern library
// (see accessPathPatterns in access_telemetry.go) is active. The
// args-fallback in NoteFromArgs covers the locale-bound cases where the
// system message omits the path entirely (cmd.exe on Turkish / German /
// Japanese Windows, etc.).
func newAccessTelemetry() *accessTelemetry { return newAccessTelemetryCore() }
