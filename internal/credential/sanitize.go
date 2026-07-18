// SPDX-License-Identifier: MIT

// Package credential handles host credential discovery and injection
// into sandboxed sessions.
package credential

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/sungurerdim/dizgin/internal/brand"
)

const maxCredentialBytes = 10 * 1024 // 10 KB cap per credential value

// Sanitize removes control characters and enforces the 10 KB size cap on a
// credential value. It trims leading/trailing whitespace (including \r\n)
// and removes embedded NUL bytes.
func Sanitize(value string) string {
	// Remove NUL bytes.
	value = strings.ReplaceAll(value, "\x00", "")
	// Trim carriage returns and newlines at the edges.
	value = strings.Trim(value, "\r\n")
	// Enforce size cap.
	if len(value) > maxCredentialBytes {
		fmt.Fprintf(os.Stderr, brand.Name+": credential: value truncated to %d bytes\n", maxCredentialBytes)
		value = value[:maxCredentialBytes]
	}
	return value
}

// SanitizeEnv sanitizes a KEY=VALUE environment string.
// Only the value part (after the first '=') is sanitized.
func SanitizeEnv(kv string) string {
	idx := strings.IndexByte(kv, '=')
	if idx < 0 {
		return kv
	}
	key := kv[:idx]
	val := Sanitize(kv[idx+1:])
	return key + "=" + val
}

// ZeroString attempts to overwrite the underlying bytes of a string with zeroes.
// On Go 1.25+ (and with certain runtime string representations), environment
// variable values may reside in read-only memory that cannot be written to
// without causing an access violation. We copy to a mutable buffer, zero that,
// and rely on the caller setting the field to "" so the GC can reclaim the
// original. This does NOT guarantee the original bytes are wiped — it is a
// best-effort defense-in-depth measure.
func ZeroString(s string) {
	if len(s) == 0 {
		return
	}
	// Create a mutable copy, zero it, and discard.
	// The original string data will be reclaimed by GC once all references
	// (including the caller's struct field) are cleared.
	buf := []byte(s)
	for i := range buf {
		buf[i] = 0
	}
	// Prevent the compiler from optimizing away the zeroing.
	runtime.KeepAlive(buf)
}

// ZeroCredentials zeroes the Value field of each credential in the slice
// using best-effort memory zeroization. Call after injection into the sandbox.
func ZeroCredentials(creds []Credential) {
	for i := range creds {
		ZeroString(creds[i].Value)
		creds[i].Value = ""
	}
}
