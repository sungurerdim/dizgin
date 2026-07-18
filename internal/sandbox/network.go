// SPDX-License-Identifier: MIT

package sandbox

import "github.com/sungurerdim/dizgin/internal/config"

// NetworkPolicy controls outbound network access from the sandbox.
//
// Re-exported as a type alias from internal/config so backend
// implementations (restricted, seatbelt, bubblewrap) can consume the
// sandbox-level abstraction without importing the config package directly.
// The alias preserves identity — sandbox.PolicyOpen and config.NetworkOpen
// are the exact same string constant, so existing call sites that already
// pass config.NetworkPolicy continue to compile.
type NetworkPolicy = config.NetworkPolicy

const (
	PolicyOpen      = config.NetworkOpen
	PolicyAllowlist = config.NetworkAllowlist
	PolicyBlocked   = config.NetworkBlocked
)
