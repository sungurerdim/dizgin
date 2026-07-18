// SPDX-License-Identifier: MIT

//go:build !windows

// Package restricted is only available on Windows.
// This file provides a no-op compile target for non-Windows platforms so
// the cross-platform `dizgin` build still type-checks even when the import
// graph references the package.
package restricted
