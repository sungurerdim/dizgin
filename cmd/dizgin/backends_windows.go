// SPDX-License-Identifier: MIT

//go:build windows

package main

// Register the Windows sandbox backend.
//
// iter6 ships `restricted` as the sole Windows production path
// (CreateRestrictedToken + Medium IL + Job + per-child mitigation
// policy bitfield + DACL DENY on sensitive paths). The iter5
// AppContainer backend was retired in iter6 Phase 4 to fix
// CLAUDE-HANG-01 (ACG ↔ Bun JIT collision); no in-tree rollback is
// available — see docs/ROADMAP.md for the WFP DNS allowlist path
// that lands network-allowlist support on the new backend.
import (
	_ "github.com/sungurerdim/dizgin/internal/sandbox/restricted"
)
