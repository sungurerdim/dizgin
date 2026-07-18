// SPDX-License-Identifier: MIT

package credential

import (
	"os"
	"runtime"
)

// SSHAgentSocket returns the path or name of the host SSH agent socket/pipe.
// On Windows, the OpenSSH agent uses a named pipe.
// On Unix, SSH_AUTH_SOCK is the standard environment variable.
func SSHAgentSocket() string {
	switch runtime.GOOS {
	case "windows":
		return windowsSSHAgentPipe()
	default:
		return os.Getenv("SSH_AUTH_SOCK")
	}
}

// windowsSSHAgentPipe returns the well-known OpenSSH agent named pipe on Windows,
// or the value of SSH_AUTH_SOCK if set (some third-party agents use that).
func windowsSSHAgentPipe() string {
	// Check env first (e.g. Pageant + wsl-ssh-pageant bridge).
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		return sock
	}
	// Windows OpenSSH agent named pipe.
	return `\\.\pipe\openssh-ssh-agent`
}

// SSHAgentEnv returns the environment variable assignment that forwards the
// SSH agent socket into the sandbox. Returns "" if no agent is available.
func SSHAgentEnv() string {
	sock := SSHAgentSocket()
	if sock == "" {
		return ""
	}
	// Verify the pipe/socket exists before forwarding.
	if runtime.GOOS != "windows" {
		if _, err := os.Stat(sock); err != nil {
			return ""
		}
	}
	return "SSH_AUTH_SOCK=" + sock
}
