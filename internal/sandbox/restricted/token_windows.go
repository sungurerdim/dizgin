// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// Restricted token construction for the iter6 `restricted` backend.
//
// The iter5 AppContainer model paired a LowBox token (Low IL +
// per-profile AC SID + capability ladder) with a CreateRestrictedToken
// fallback. CLAUDE-HANG-01 root-cause analysis pointed at the ACG
// (Arbitrary Code Guard) ↔ Bun in-process JIT collision as the
// dominant cause of Bun SEA hangs; AppContainer's auto-applied ACG
// could not be disabled cleanly. Iter6 drops AppContainer entirely
// and ships a restricted Medium-IL token without LowBox, AC SID, or
// capability set — relying instead on DACL DENY ACEs (acl_windows.go)
// and a per-child process mitigation policy bitfield
// (mitigation_windows.go, ACG explicitly OFF for Bun compatibility).
//
// Why Medium IL, not Low? Low IL hard-blocks the Win32 desktop heap
// (and several inbox surfaces tools rely on, e.g. MSYS2 /dev/null
// through \\.\NUL); we recovered some of that in iter5 with
// per-resource DACL stamps, but Bun additionally interacts with named
// pipe creation and trustinfo paths that no amount of DACL stamping
// papers over. Medium IL is the same level a standard interactive
// user runs at — anything our user can already do, the sandbox child
// can also do (subject to DACL DENY + Job + mitigations + caller's
// explicit FS model).
//
// Why no SidsToDisable / RestrictedSids? Locking these down is what
// makes a token a *restricted* token in the SYSTEM sense, but it also
// disables `SeChangeNotifyPrivilege` (required for NTFS traversal of
// any path not under workdir). The iter6 model achieves comparable
// blast-radius reduction via DACL DENY on sensitive paths (.ssh,
// .aws/credentials, …) rather than blanket SID restriction. If a
// regression demands the heavier knob, `DIZGIN_RESTRICTED_MINIMAL=1`
// is the documented escape hatch — handled inside CreateRestrictedTokenForLevel.
var (
	modAdvapi32               = windows.NewLazySystemDLL("advapi32.dll")
	procCreateRestrictedToken = modAdvapi32.NewProc("CreateRestrictedToken")
)

// DISABLE_MAX_PRIVILEGE drops every privilege from the source token's
// list before producing the restricted derivative. The kernel still
// honours privilege checks against the result so anything an
// administrator's token would otherwise be able to do (load drivers,
// take ownership) is hard-blocked.
const disableMaxPrivilege = 0x1

// IntegrityLevel SIDs. String forms are stable from Win Vista onward.
// Untrusted = S-1-16-0; Low = S-1-16-4096; Medium = S-1-16-8192;
// MediumPlus = S-1-16-8448; High = S-1-16-12288.
const (
	IntegrityLevelUntrustedSid = "S-1-16-0"
	IntegrityLevelLowSid       = "S-1-16-4096"
	IntegrityLevelMediumSid    = "S-1-16-8192"
)

// TOKEN_MANDATORY_LABEL mirrors the winnt.h struct of the same name.
// Pointed at by SetTokenInformation when class == TokenIntegrityLevel.
type tokenMandatoryLabel struct {
	Label windows.SIDAndAttributes
}

// TokenIntegrityLevel = 25 — winnt.h enum.
const tokenIntegrityLevel = 25

// CreateRestrictedTokenForLevel builds a hardened restricted token
// derived from the caller's primary token at the given IL SID. The
// result has every privilege dropped (via DISABLE_MAX_PRIVILEGE) but
// retains its base SID list so NTFS traversal and named pipe access
// keep working — the FS isolation is enforced separately via the DACL
// DENY layer (acl_windows.go).
//
// ilSidString must be one of IntegrityLevel*Sid constants above. Pass
// IntegrityLevelMediumSid for the iter6 production path.
func CreateRestrictedTokenForLevel(ilSidString string) (windows.Token, error) {
	var src windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ADJUST_GROUPS|windows.TOKEN_ADJUST_PRIVILEGES,
		&src,
	); err != nil {
		return 0, fmt.Errorf("restricted: OpenProcessToken: %w", err)
	}
	defer func() { _ = src.Close() }()

	flags := uintptr(disableMaxPrivilege)
	if os.Getenv(brand.Env("RESTRICTED_MINIMAL")) == "1" {
		// Emergency rollback: skip the restricted-token wrap entirely.
		// Caller can still apply Job + mitigation layers on top of a
		// plain primary-token duplicate. See plan Risk 1.
		var dup windows.Token
		if err := windows.DuplicateTokenEx(
			src,
			windows.TOKEN_ALL_ACCESS,
			nil,
			windows.SecurityImpersonation,
			windows.TokenPrimary,
			&dup,
		); err != nil {
			return 0, fmt.Errorf("restricted: DuplicateTokenEx(minimal): %w", err)
		}
		if err := setIntegrityLevel(dup, ilSidString); err != nil {
			_ = dup.Close()
			return 0, err
		}
		return dup, nil
	}

	var restricted windows.Token
	r1, _, e := procCreateRestrictedToken.Call(
		uintptr(src),
		flags,
		0, 0, // DisableSidCount, SidsToDisable — intentionally empty (preserve SeChangeNotify)
		0, 0, // DeletePrivilegeCount, PrivilegesToDelete (DISABLE_MAX_PRIVILEGE handles all)
		0, 0, // RestrictedSidCount, SidsToRestrict — intentionally empty
		uintptr(unsafe.Pointer(&restricted)),
	)
	if r1 == 0 {
		return 0, fmt.Errorf("restricted: CreateRestrictedToken: %w", e)
	}

	if err := setIntegrityLevel(restricted, ilSidString); err != nil {
		_ = restricted.Close()
		return 0, err
	}
	return restricted, nil
}

// CreateRestrictedTokenMediumIL is the production helper used by the
// `restricted` backend. Equivalent to CreateRestrictedTokenForLevel with
// IntegrityLevelMediumSid.
func CreateRestrictedTokenMediumIL() (windows.Token, error) {
	return CreateRestrictedTokenForLevel(IntegrityLevelMediumSid)
}

// setIntegrityLevel sets a token's mandatory label by SID string.
// The matching label SID is allocated, wrapped in a TOKEN_MANDATORY_LABEL
// and passed to SetTokenInformation. The OS owns the SID once the call
// returns; we free our allocation eagerly to avoid leaking on the slow
// path.
func setIntegrityLevel(token windows.Token, sidString string) error {
	pStr, err := windows.UTF16PtrFromString(sidString)
	if err != nil {
		return fmt.Errorf("restricted: IL SID UTF16: %w", err)
	}
	var sid *windows.SID
	if err := windows.ConvertStringSidToSid(pStr, &sid); err != nil {
		return fmt.Errorf("restricted: ConvertStringSidToSid(%q): %w", sidString, err)
	}
	defer func() { _ = windows.FreeSid(sid) }()

	label := tokenMandatoryLabel{
		Label: windows.SIDAndAttributes{Sid: sid, Attributes: 0x00000020}, // SE_GROUP_INTEGRITY
	}
	if err := windows.SetTokenInformation(
		token,
		uint32(tokenIntegrityLevel),
		(*byte)(unsafe.Pointer(&label)),
		uint32(unsafe.Sizeof(label)),
	); err != nil {
		return fmt.Errorf("restricted: SetTokenInformation(IntegrityLevel): %w", err)
	}
	return nil
}

// TokenIntegrityLevelSID returns the IL SID of `tok` as a string
// (e.g. "S-1-16-8192" for Medium). Used by tests + diagnostics to
// verify CreateRestrictedTokenForLevel applied the requested label.
func TokenIntegrityLevelSID(tok windows.Token) (string, error) {
	// First call: get required buffer size.
	var size uint32
	_ = windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, nil, 0, &size)
	if size == 0 {
		return "", fmt.Errorf("restricted: GetTokenInformation(IntegrityLevel) size==0")
	}
	buf := make([]byte, size)
	if err := windows.GetTokenInformation(
		tok,
		windows.TokenIntegrityLevel,
		&buf[0],
		size,
		&size,
	); err != nil {
		return "", fmt.Errorf("restricted: GetTokenInformation(IntegrityLevel): %w", err)
	}
	label := (*tokenMandatoryLabel)(unsafe.Pointer(&buf[0]))
	if label.Label.Sid == nil {
		return "", fmt.Errorf("restricted: IL SID nil after GetTokenInformation")
	}
	return label.Label.Sid.String(), nil
}
