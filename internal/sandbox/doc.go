// SPDX-License-Identifier: MIT

// Package sandbox defines the Backend and Box interfaces implemented by each
// platform-specific sandbox backend (restricted (Windows), Seatbelt (macOS),
// bubblewrap (Linux)). It provides a registry for backend registration and
// lookup by name.
package sandbox
