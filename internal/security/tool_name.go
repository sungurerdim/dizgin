// SPDX-License-Identifier: MIT

package security

import (
	"errors"
	"fmt"
	"strings"
)

// ValidateToolName rejects tool names that could escape the profiles/
// permissions directory when joined into a per-tool YAML file path (e.g.
// via "../../etc/cron.d/evil"). Every dizgin subsystem that derives such a
// path from a user- or env-supplied tool name (--tool, $DIZGIN_TOOL) must
// call this before the filepath.Join that builds the on-disk path.
func ValidateToolName(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return errors.New("security: empty tool name")
	}
	if strings.ContainsAny(trimmed, `/\`) || strings.Contains(trimmed, "..") {
		return fmt.Errorf("security: invalid tool name %q (path separators and \"..\" are not allowed)", name)
	}
	return nil
}
