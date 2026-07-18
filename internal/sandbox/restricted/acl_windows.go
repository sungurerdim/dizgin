// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/log"
)

// DACL stamping for the iter6 `restricted` backend.
//
// The iter5 AppContainer backend stamped a per-session AC SID with
// GRANT ACEs on every mount. iter6 inverts the model:
//
//   - GRANT stamps are mostly unnecessary — the spawned process runs
//     as the same user as dizgin and already has natural access to its
//     own files. GRANT is kept on the surface for the edge cases
//     where a workdir lives on a foreign-owned volume (network share,
//     externally-mounted disk) and the user needs an explicit ACE.
//   - DENY stamps are the iter6 enforcement layer. Applied on
//     session start to every path in security.SensitiveDenyPaths,
//     revoked on Cleanup. Windows DACL semantics evaluate deny ACEs
//     before allow ACEs (and SetEntriesInAcl writes them in
//     canonical order) so the DENY wins regardless of which other
//     allow ACEs already live on the path.
//
// Failure mode: a partial stamp pass that crashes mid-way leaves DENY
// ACEs on the user's own files. The user is the path owner; their
// implicit WRITE_DAC right still lets them revoke. The orphan sweeper
// reads the audit JSONL to recover automatically on next dizgin run.
var aclTimingEnabled = log.IsTimingEnabled()

// UNPROTECTED_DACL_SECURITY_INFORMATION is winnt.h's flag indicating
// the DACL allows inheritance from its parent. Passing this alongside
// DACL_SECURITY_INFORMATION on SetNamedSecurityInfo sets the
// SE_DACL_AUTO_INHERITED control bit, which tells the kernel to manage
// inheritance propagation using the modern (post-Win2k) semantics —
// including propagation of REMOVALS when an inheritable ACE is dropped
// from a parent. Without it, the kernel keeps the legacy behaviour
// where ADD propagates but REMOVE does not, and the user is locked out
// of their own files after a session ends.
//
// golang.org/x/sys/windows does not export this constant; we declare
// it locally and cast at the call site.
const unprotectedDACLSecurityInformation uint32 = 0x20000000

// daclSetInfo is the SecurityInformation argument for SET-side calls
// (SetNamedSecurityInfo). The UNPROTECTED_DACL bit is set-only — it
// instructs the kernel to clear SE_DACL_PROTECTED on the target so
// auto-inheritance is enabled.
func daclSetInfo() windows.SECURITY_INFORMATION {
	return windows.SECURITY_INFORMATION(uint32(windows.DACL_SECURITY_INFORMATION) | unprotectedDACLSecurityInformation)
}

// daclGetInfo is the SecurityInformation argument for GET-side calls
// (GetNamedSecurityInfo). UNPROTECTED_DACL is documented as a set-only
// modifier; passing it to Get can produce wrong results.
func daclGetInfo() windows.SECURITY_INFORMATION {
	return windows.DACL_SECURITY_INFORMATION
}

// stampMode picks the AccessMode field on the EXPLICIT_ACCESS we append.
// Internal — callers use StampPathGrant / StampPathDeny.
type stampMode int

const (
	stampModeGrant stampMode = iota
	stampModeDeny
)

// StampPathGrant appends a GRANT ACE on dir for trustee. readOnly maps
// to FILE_GENERIC_READ + FILE_TRAVERSE (mirrors iter4 R1-C semantics
// — read + descend, no execute, so a junction-pointing-at-bin attack
// can't launch binaries through the mount).
//
// In the restricted backend the GRANT path is rarely needed; most
// session paths are owned by the user already. Kept for foreign-
// owned volume mounts.
func StampPathGrant(dir string, trustee *windows.SID, readOnly bool) error {
	if trustee == nil {
		return fmt.Errorf("restricted: StampPathGrant: nil trustee")
	}
	return stampPathNative(dir, trustee, stampModeGrant, readOnly)
}

// StampPathDeny appends a DENY ACE on dir for trustee, full access
// mask (GENERIC_ALL). SetEntriesInAcl places the new ACE before any
// existing GRANT ACEs in the resulting DACL, so the kernel evaluates
// deny first and the trustee loses every right on dir + descendants.
//
// readOnly is unused for DENY — partial denies (block read, allow
// write) make no security sense for credential paths. The DENY ACE
// inherits (OI/CI) into every child file and subdir.
func StampPathDeny(dir string, trustee *windows.SID) error {
	if trustee == nil {
		return fmt.Errorf("restricted: StampPathDeny: nil trustee")
	}
	return stampPathNative(dir, trustee, stampModeDeny, false)
}

// RevokePathForTrustee removes every ACE whose trustee SID matches
// trustee from dir's DACL. Used by Cleanup to undo session-applied
// DENY (and GRANT) stamps.
//
// The path owner retains implicit WRITE_DAC even when the DACL DENYs
// them every other right, so this call still succeeds against the
// trustee's own credential paths (.ssh, .aws/credentials, ...) — the
// user is the canonical owner on every entry in the SSOT.
func RevokePathForTrustee(dir string, trustee *windows.SID) error {
	return RevokePathForTrusteeCtx(context.Background(), dir, trustee)
}

// RevokePathForTrusteeCtx is the context-aware variant. Native ACL
// operations do not spawn subprocesses so ctx is informational —
// callers pass it through revokeStampsParallel so a deadline can
// trigger short-circuit logic at the dispatch level.
func RevokePathForTrusteeCtx(_ context.Context, dir string, trustee *windows.SID) error {
	if trustee == nil {
		return nil
	}
	return revokePathNative(dir, trustee)
}

// CurrentUserSID returns the SID of the process token's user. Wraps
// OpenProcessToken + GetTokenUser so callers do not need to manage the
// token handle. Returned SID is allocated via Go heap (escape from
// the syscall struct) and remains valid for the caller's lifetime.
func CurrentUserSID() (*windows.SID, error) {
	var tok windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_QUERY,
		&tok,
	); err != nil {
		return nil, fmt.Errorf("restricted: OpenProcessToken: %w", err)
	}
	defer func() { _ = tok.Close() }()

	user, err := tok.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("restricted: GetTokenUser: %w", err)
	}
	// Copy the SID off the syscall struct — the underlying memory is
	// owned by the token handle, which Close() releases on return.
	copy, err := user.User.Sid.Copy()
	if err != nil {
		return nil, fmt.Errorf("restricted: Sid.Copy: %w", err)
	}
	return copy, nil
}

// buildDenyDacl merges a single new EXPLICIT_ACCESS entry for trustee into
// existing and returns the resulting *windows.ACL. This is a pure data
// transformation — it contains no syscalls other than ACLFromEntries.
//
// ACLFromEntries wraps SetEntriesInAcl, which produces a canonical ACL:
// deny ACEs at the front, allow ACEs after. Even if existing already had a
// GRANT ACE for trustee, our new DENY lands ahead of it in the output.
func buildDenyDacl(dir string, trustee *windows.SID, mode stampMode, readOnly bool, existing *windows.ACL) (*windows.ACL, error) {
	perm := uint32(windows.GENERIC_ALL)
	if readOnly && mode == stampModeGrant {
		perm = uint32(windows.FILE_GENERIC_READ | windows.FILE_TRAVERSE)
	}

	var winMode windows.ACCESS_MODE = windows.GRANT_ACCESS
	if mode == stampModeDeny {
		winMode = windows.DENY_ACCESS
	}

	entry := windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.ACCESS_MASK(perm),
		AccessMode:        winMode,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(trustee),
		},
	}

	merged, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{entry}, existing)
	if err != nil {
		return nil, fmt.Errorf("restricted: ACLFromEntries on %s: %w", dir, err)
	}
	return merged, nil
}

func stampPathNative(dir string, trustee *windows.SID, mode stampMode, readOnly bool) error {
	if trustee == nil {
		return fmt.Errorf("restricted: stampPathNative: nil trustee")
	}
	t0 := time.Now()
	defer func() {
		if aclTimingEnabled {
			label := "grant"
			if mode == stampModeDeny {
				label = "deny"
			}
			fmt.Fprintf(os.Stderr, brand.Name+": stamp %.3fs %s mode=%s ro=%v\n",
				time.Since(t0).Seconds(), dir, label, readOnly)
		}
	}()

	sd, err := windows.GetNamedSecurityInfo(
		dir, windows.SE_FILE_OBJECT, daclGetInfo(),
	)
	if err != nil {
		return fmt.Errorf("restricted: GetNamedSecurityInfo on %s: %w", dir, err)
	}
	existing, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("restricted: read DACL on %s: %w", dir, err)
	}

	merged, err := buildDenyDacl(dir, trustee, mode, readOnly, existing)
	if err != nil {
		return err
	}

	if err := windows.SetNamedSecurityInfo(
		dir, windows.SE_FILE_OBJECT, daclSetInfo(),
		nil, nil, merged, nil,
	); err != nil {
		return fmt.Errorf("restricted: SetNamedSecurityInfo on %s: %w", dir, err)
	}
	return nil
}

func revokePathNative(dir string, trustee *windows.SID) error {
	if trustee == nil {
		return nil
	}
	// Step 1: remove the explicit ACE from the root.
	if err := revokeSingleACE(dir, trustee); err != nil {
		return err
	}
	// Step 2: walk descendants and strip the now-stale INHERITED_ACE
	// copies. The Windows kernel auto-propagates ADDITIONS of
	// inheritable ACEs to existing children when a parent's DACL is
	// modified, but it does NOT auto-propagate REMOVALS — children
	// keep their inherited copy after a parent revoke. Without this
	// walk, the user's own access to .ssh/id_rsa stays denied after
	// the session ends. TreeSetNamedSecurityInfo could do the same
	// job in a single syscall but it is not exposed by
	// golang.org/x/sys/windows; the per-node walk is correct and
	// fast enough — the SSOT paths are bounded (largest is
	// ~/AppData/Roaming/Mozilla/Firefox/Profiles, on the order of
	// hundreds of files).
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() {
		return nil
	}
	_ = filepath.WalkDir(dir, func(path string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil || path == dir {
			return nil
		}
		_ = revokeSingleACE(path, trustee)
		return nil
	})
	return nil
}

// revokeSingleACE strips every ACE for trustee from the single named
// object's DACL.
//
// IMPORTANT: SetEntriesInAcl's REVOKE_ACCESS mode is asymmetric — per
// MSDN it removes ACCESS_ALLOWED entries only, never ACCESS_DENIED.
// SET_ACCESS by contrast "will discard any existing ACEs that grant
// or deny the trustee specified access rights" before adding the new
// (zero-permission) grant. We exploit that to drop both DENY and
// GRANT ACEs for trustee in one call; the resulting zero-permission
// grant occupies a single canonical ACE that does not affect access
// checks (the path owner's implicit rights remain).
func revokeSingleACE(path string, trustee *windows.SID) error {
	sd, err := windows.GetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT, daclGetInfo(),
	)
	if err != nil {
		return fmt.Errorf("restricted: GetNamedSecurityInfo on %s: %w", path, err)
	}
	existing, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("restricted: read DACL on %s: %w", path, err)
	}
	entry := windows.EXPLICIT_ACCESS{
		AccessPermissions: 0,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(trustee),
		},
	}
	merged, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{entry}, existing)
	if err != nil {
		return fmt.Errorf("restricted: ACLFromEntries revoke on %s: %w", path, err)
	}
	if err := windows.SetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT, daclSetInfo(),
		nil, nil, merged, nil,
	); err != nil {
		return fmt.Errorf("restricted: SetNamedSecurityInfo revoke on %s: %w", path, err)
	}
	return nil
}
