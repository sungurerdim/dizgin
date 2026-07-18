// SPDX-License-Identifier: MIT

// Package profiles embeds the bundled tool profile YAML files so they are
// always available inside the dizgin binary regardless of the installation layout.
package profiles

import "embed"

//go:embed *.yaml
var FS embed.FS
