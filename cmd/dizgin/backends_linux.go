// SPDX-License-Identifier: MIT

//go:build linux

package main

// Import the Linux bubblewrap backend so its init() registers it.
import _ "github.com/sungurerdim/dizgin/internal/sandbox/bubblewrap"
