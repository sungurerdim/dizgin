// SPDX-License-Identifier: MIT

// Package platform detects the current OS and maps it to a sandbox backend name.
// It also provides suspend/resume and focus-window utilities. Sandbox sub-packages
// may import platform, but platform must not import sandbox to keep the graph acyclic.
package platform
