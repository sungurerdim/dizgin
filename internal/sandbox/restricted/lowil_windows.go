// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// Low-IL (Mandatory Integrity Control) write-scoping for R3 (host
// integrity). EXPERIMENTAL, flag-gated via DIZGIN_LOW_IL=1.
//
// When enabled the child runs at Low integrity (S-1-16-4096) instead of
// Medium. Windows MIC's default no-write-up policy then lets the child
// READ every Medium object (read-up is permitted) but blocks WRITE and
// DELETE on them — so the user's home, system dirs, and unrelated data
// are protected from a runaway tool, while reads stay native. The
// writable set (per-session scratch, and — once wired — workdir + tool
// config dirs + the stdio/ConPTY pipes) is explicitly relabelled Low so
// the child can write exactly there and nowhere else.
//
// This is the user-mode path proven by the 2026-05-30 spike: a Low-IL
// console child starts cleanly (unlike a WRITE_RESTRICTED token, which
// dies at init), reads broadly, and writes only Low-labelled targets.
//
// Default OFF — the Medium-IL path (CreateRestrictedTokenMediumIL) is
// unchanged when the flag is absent.

// labelSecurityInformation is SECURITY_INFORMATION's LABEL bit. Passing
// it to SetNamedSecurityInfo writes the object's mandatory (integrity)
// label SACL. golang.org/x/sys/windows does not export the constant.
const labelSecurityInformation = 0x00000010

// lowILEnabled reports whether the experimental Low-IL write-scoping
// mode is on. Read at the env each call (matches the other DIZGIN_* runtime
// switches; cheap map lookup).
func lowILEnabled() bool {
	return os.Getenv(brand.Env("LOW_IL")) == "1"
}

// lowLabelSDDL is the SDDL fragment that labels an object Low integrity
// with the no-write-up policy, inheritable to children (OICI). A Low
// subject writing to a Low object is an equal-level write (allowed); a
// Medium subject (dizgin, the user's other apps) writing down to it is also
// allowed — so relabelling a path Low does not lock the user out.
const lowLabelSDDL = "S:(ML;OICI;NW;;;LW)"

// setLowLabelPath stamps a Low integrity label on dir (inheritable), so
// a Low-IL child may write inside it. Cleanup does not need to strip the
// label explicitly for scratch (the whole tree is deleted), but workdir
// labelling — once added — must be reverted; see the revoke path.
func setLowLabelPath(dir string) error {
	sd, err := windows.SecurityDescriptorFromString(lowLabelSDDL)
	if err != nil {
		return fmt.Errorf("restricted: low-label SDDL: %w", err)
	}
	sacl, _, err := sd.SACL()
	if err != nil {
		return fmt.Errorf("restricted: low-label SACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(
		dir, windows.SE_FILE_OBJECT,
		windows.SECURITY_INFORMATION(labelSecurityInformation),
		nil, nil, nil, sacl,
	); err != nil {
		return fmt.Errorf("restricted: set low label on %s: %w", dir, err)
	}
	return nil
}

// mediumLabelSDDL relabels an object back to Medium (the implicit
// default). Used on cleanup to revert a workdir / tool-dir that was
// lowered to Low for the session. Inheritance removal on already-created
// children is best-effort (Windows does not auto-propagate label
// removals) — newly created files may retain an inherited Low label;
// documented limitation of the experimental mode.
const mediumLabelSDDL = "S:(ML;OICI;NW;;;ME)"

// removeLowLabelPath reverts dir's mandatory label to Medium.
func removeLowLabelPath(dir string) error {
	sd, err := windows.SecurityDescriptorFromString(mediumLabelSDDL)
	if err != nil {
		return fmt.Errorf("restricted: medium-label SDDL: %w", err)
	}
	sacl, _, err := sd.SACL()
	if err != nil {
		return fmt.Errorf("restricted: medium-label SACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(
		dir, windows.SE_FILE_OBJECT,
		windows.SECURITY_INFORMATION(labelSecurityInformation),
		nil, nil, nil, sacl,
	); err != nil {
		return fmt.Errorf("restricted: revert label on %s: %w", dir, err)
	}
	return nil
}

// lowILTokenLevel returns the integrity-level SID string the box should
// build its restricted token at, honouring the DIZGIN_LOW_IL switch.
func lowILTokenLevel() string {
	if lowILEnabled() {
		return IntegrityLevelLowSid
	}
	return IntegrityLevelMediumSid
}

// isAccessDenied reports whether err wraps Windows ERROR_ACCESS_DENIED
// (5) — the failure setLowLabelPath returns when the caller lacks
// WRITE_OWNER on the target. Used to gate the owner self-ACE retry so a
// genuinely different failure (path gone, name too long) is not masked.
func isAccessDenied(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED)
}

// ownedBySID reports whether dir's owner SID equals want. The Low-relabel
// self-ACE retry is gated on this: only the owner holds the implicit
// WRITE_DAC that lets addSelfFullACE rewrite the DACL without already
// having an explicit ACE. Any failure to read the owner returns false
// (fail-safe: skip the retry rather than grant on an unverified owner).
func ownedBySID(dir string, want *windows.SID) bool {
	if want == nil {
		return false
	}
	sd, err := windows.GetNamedSecurityInfo(
		dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false
	}
	return owner.Equals(want)
}

// addSelfFullACE adds a non-inheriting GENERIC_ALL allow ACE for trustee
// on dir, preserving every existing ACE. The ACE is deliberately NOT
// inheritable: its only job is to grant the WRITE_OWNER that the
// mandatory-label write needs on dir itself; the Low label (OICI) handles
// child integrity, and the child writes children via its own user rights.
// Revoked by revokeSelfFullACE in Cleanup.
func addSelfFullACE(dir string, trustee *windows.SID) error {
	if trustee == nil {
		return fmt.Errorf("restricted: addSelfFullACE: nil trustee")
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, daclGetInfo())
	if err != nil {
		return fmt.Errorf("restricted: GetNamedSecurityInfo on %s: %w", dir, err)
	}
	existing, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("restricted: read DACL on %s: %w", dir, err)
	}
	entry := windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.ACCESS_MASK(windows.GENERIC_ALL),
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(trustee),
		},
	}
	merged, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{entry}, existing)
	if err != nil {
		return fmt.Errorf("restricted: ACLFromEntries on %s: %w", dir, err)
	}
	if err := windows.SetNamedSecurityInfo(
		dir, windows.SE_FILE_OBJECT, daclSetInfo(),
		nil, nil, merged, nil,
	); err != nil {
		return fmt.Errorf("restricted: SetNamedSecurityInfo on %s: %w", dir, err)
	}
	return nil
}

// revokeSelfFullACE strips the temporary self-ACE addSelfFullACE added to
// dir. Reuses revokeSingleACE (SET_ACCESS, zero perms, non-recursive) —
// the self-ACE was non-inheriting so no descendant walk is needed.
func revokeSelfFullACE(dir string, trustee *windows.SID) error {
	return revokeSingleACE(dir, trustee)
}
