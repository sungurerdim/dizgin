// SPDX-License-Identifier: MIT

//go:build !windows

package log

// StartAggregator and StopAggregator are no-ops on non-Windows
// platforms. The aggregator is a Windows debugging convenience: it
// merges the broker / runhcs / shim / vm log streams into a single
// chronologically-ordered file. macOS (seatbelt) and Linux
// (bubblewrap) backends do not produce per-layer logs that need
// merging, so the feature has no equivalent there yet.
func StartAggregator() {}
func StopAggregator()  {}
