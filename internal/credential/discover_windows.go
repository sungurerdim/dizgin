// SPDX-License-Identifier: MIT

//go:build windows

package credential

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var (
	advapi32      = syscall.NewLazyDLL("advapi32.dll")
	procCredReadW = advapi32.NewProc("CredReadW")
	procCredFree  = advapi32.NewProc("CredFree")
)

const credTypeGeneric = 1 // CRED_TYPE_GENERIC

// credential mirrors the CREDENTIALW Win32 struct (partial — only fields we read).
type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        uint64 // FILETIME
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

// PlatformConfigDirs returns Windows-specific configuration directories that
// may contain credentials for AI tools. These are used for mount planning.
func PlatformConfigDirs() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		appdata = filepath.Join(home, "AppData", "Roaming")
	}
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		localAppData = filepath.Join(home, "AppData", "Local")
	}

	candidates := []string{
		filepath.Join(home, ".anthropic"),
		filepath.Join(appdata, "Claude"),
		filepath.Join(appdata, "claude-code"),
		filepath.Join(appdata, "OpenAI"),
		filepath.Join(home, ".codex"),
		filepath.Join(home, ".aider"),
		filepath.Join(home, ".gemini"),
		filepath.Join(localAppData, "opencode"),
	}

	var existing []string
	for _, d := range candidates {
		if _, err := os.Stat(d); err == nil {
			existing = append(existing, d)
		}
	}
	return existing
}

// DiscoverCredManagerSecret reads a generic credential from the Windows
// Credential Manager by target name. Returns empty string if not found.
func DiscoverCredManagerSecret(target string) string {
	targetPtr, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return ""
	}

	var cred *credential
	ret, _, _ := procCredReadW.Call(
		uintptr(unsafe.Pointer(targetPtr)),
		uintptr(credTypeGeneric),
		0, // Reserved
		uintptr(unsafe.Pointer(&cred)),
	)
	if ret == 0 || cred == nil {
		return "" // not found or access denied
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(cred))) //nolint:errcheck // CredFree has no meaningful error

	if cred.CredentialBlobSize == 0 || cred.CredentialBlob == nil {
		return ""
	}

	// Copy the blob bytes out before CredFree.
	blob := unsafe.Slice(cred.CredentialBlob, cred.CredentialBlobSize)
	val := string(blob)

	// The blob may be UTF-16 encoded (Windows convention). If the first two
	// bytes look like a valid ASCII char + NUL, decode as UTF-16.
	if len(blob) >= 2 && blob[1] == 0 && blob[0] >= 0x20 && blob[0] <= 0x7e {
		val = utf16BytesToString(blob)
	}

	return Sanitize(strings.TrimSpace(val))
}

// utf16BytesToString decodes a UTF-16LE byte slice to a Go string.
func utf16BytesToString(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	// Trim trailing NUL.
	for len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	return syscall.UTF16ToString(u16)
}

// ScanCredManagerAPIKeys attempts to retrieve well-known API keys from the
// Windows Credential Manager. This supplements environment variable discovery.
func ScanCredManagerAPIKeys() []Credential {
	// Well-known target names that AI tool installers may store credentials under.
	targets := []struct {
		target string
		envKey string
	}{
		{"ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"},
		{"OPENAI_API_KEY", "OPENAI_API_KEY"},
		{"GEMINI_API_KEY", "GEMINI_API_KEY"},
	}

	var creds []Credential
	for _, t := range targets {
		val := DiscoverCredManagerSecret(t.target)
		if val != "" {
			creds = append(creds, Credential{
				Key:    t.envKey,
				Value:  val,
				Source: "credential-manager",
			})
		}
	}
	return creds
}

// PlatformDiscover performs Windows-specific credential discovery (Credential Manager).
// It returns discovered credentials that are not already present in existing.
func PlatformDiscover(existing []Credential) []Credential {
	credManagerCreds := ScanCredManagerAPIKeys()
	var extra []Credential
	for _, c := range credManagerCreds {
		if !hasCred(existing, c.Key) {
			extra = append(extra, c)
		}
	}
	return extra
}
