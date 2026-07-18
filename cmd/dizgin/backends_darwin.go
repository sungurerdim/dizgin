// SPDX-License-Identifier: MIT

//go:build darwin

package main

// Import the macOS Seatbelt backend so its init() registers it.
import _ "github.com/sungurerdim/dizgin/internal/sandbox/seatbelt"
