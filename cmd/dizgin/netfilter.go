// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"

	"github.com/sungurerdim/dizgin/internal/audit"
	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/config"
	"github.com/sungurerdim/dizgin/internal/daemon"
)

// wfpEnabled reports whether the session should attempt user-mode WFP
// network enforcement: a non-empty allowlist policy and the DIZGIN_NO_WFP
// emergency switch not set. Mirrors the env-switch pattern of the other
// defense layers (DIZGIN_NO_TEMP_OVERRIDE, DIZGIN_NO_HANDLE_LIST).
func wfpEnabled(cfg *config.Config) bool {
	if os.Getenv(brand.Env("NO_WFP")) == "1" {
		return false
	}
	return cfg.Network.Policy == config.NetworkAllowlist && len(cfg.Network.Allowlist) > 0
}

// applyNetworkFilter brokers the WFP allowlist through the elevated
// dizgind daemon (dizgin runs non-elevated and cannot add WFP filters
// itself). On any failure the session degrades to advisory: a single
// stderr line explains that egress is unrestricted. Network enforcement
// is the accidental-egress interim, not the hard boundary (that is R1
// filesystem), so a failure here must never abort the tool.
func applyNetworkFilter(cfg *config.Config, sessionID, toolPath string) {
	if !wfpEnabled(cfg) {
		return
	}
	summary, err := daemon.ApplyNetworkFilter(sessionID, toolPath, cfg.Network.Allowlist)
	if err != nil {
		audit.NetworkEnforce(sessionID, false, err.Error())
		fmt.Fprintf(os.Stderr, brand.Name+": network allowlist not enforced (%v) — egress is unrestricted this session. "+
			"Start the dizgind daemon (elevated) for WFP enforcement, or set DIZGIN_NO_WFP=1 to silence.\n", err)
		return
	}
	audit.NetworkEnforce(sessionID, true, summary)
	fmt.Fprintf(os.Stderr, brand.Name+": network allowlist enforced via WFP: %s\n", summary)
}

// revokeNetworkFilter tears down the session's WFP filters at exit.
// Best-effort: the daemon's dynamic WFP session auto-reaps the filters if
// the revoke never arrives (daemon restart / dizgin crash).
func revokeNetworkFilter(cfg *config.Config, sessionID string) {
	if !wfpEnabled(cfg) {
		return
	}
	_ = daemon.RevokeNetworkFilter(sessionID)
}
