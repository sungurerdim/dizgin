// SPDX-License-Identifier: MIT

package main

import (
	"os/exec"
)

// lookPath finds the full path of the named binary using exec.LookPath.
func lookPath(name string) (string, error) {
	return exec.LookPath(name)
}
