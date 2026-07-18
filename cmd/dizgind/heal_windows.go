// SPDX-License-Identifier: MIT

//go:build windows

package main

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

	"github.com/sungurerdim/dizgin/internal/security"

	// Blank import to ensure restricted's init() fires and wires
	// security.RevokePathForTrustee before heal calls it (ARC-05).
	_ "github.com/sungurerdim/dizgin/internal/sandbox/restricted"
)

// dizgind heal — iter7 post-incident recovery v2.
//
// Inventories every path in security.SensitiveDenyPaths and inspects
// its DACL. Two failure classes are reported:
//
//	DRIFT  — an ACCESS_ALLOWED ACE for a trustee outside the expected
//	         set (SYSTEM, Administrators, current user). The 2026-05-17
//	         family of bugs (inheritance leak from a parent ACL change,
//	         third-party installer over-granting Everyone:F on the
//	         user profile, etc.) all show up here.
//	ORPHAN — an ACCESS_DENIED ACE left behind on disk. Each dizgin session
//	         applies DENY ACEs at start and revokes them at exit; a
//	         deny ACE present *between* sessions means a previous dizgin
//	         died before Cleanup could run.
//
// Default mode is --report (read-only, requires no admin). --apply
// revokes the offending trustee via SET_ACCESS-zero-perms (same
// primitive Box.Cleanup uses, see internal/sandbox/restricted/
// acl_windows.go::RevokePathForTrustee). Revoke succeeds when the
// running user has WRITE_DAC on the target path; for paths the user
// owns (everything under USERPROFILE) that is the default.
//
// heal does NOT add any ACEs back — restoring the canonical ACL is
// the job of the OS install / user-profile defaults, not heal. If
// removing the drift trustee leaves the path with no ALLOW ACE the
// user keeps implicit owner WRITE_DAC and can re-grant whatever
// they intended through icacls.

var (
	healApplyFlag bool
)

var healCmd = &cobra.Command{
	Use:   "heal",
	Short: "Scan the sensitive SSOT for ACL drift and (optionally) revoke",
	Long: `Inventories internal/security.SensitiveDenyPaths and reports DACL
drift on each present path. Categories:

  DRIFT  : an allow ACE for a trustee outside {SYSTEM, Administrators,
           current user}. Includes the Everyone / Authenticated Users /
           ALL APPLICATION PACKAGES / generic-Users leak families.
  ORPHAN : a deny ACE left behind by a crashed dizgin session.

  --report  (default) read-only — just lists drift and exits 0.
  --apply              revokes the drift / orphan trustee via
                       security.RevokePathForTrustee. Requires
                       WRITE_DAC on the target path (default for
                       paths the user owns).
  --yes                skip the per-trustee confirmation prompt in
                       --apply mode. Useful for unattended runs.

dizgind heal is the iter7 successor to the retired dizgind setup
--repair / dizgin audit-low / dizgin unstamp trio.`,
	RunE: runHeal,
}

var healYesFlag bool

func init() {
	healCmd.Flags().BoolVar(&healApplyFlag, "apply", false, "Apply revoke instead of just reporting drift")
	healCmd.Flags().BoolVar(&healYesFlag, "yes", false, "Skip the per-trustee confirmation prompt in --apply mode")
	rootCmd.AddCommand(healCmd)
}

func runHeal(_ *cobra.Command, _ []string) error {
	home := os.Getenv("USERPROFILE")
	if home == "" {
		return fmt.Errorf("dizgind heal: USERPROFILE empty — cannot expand SSOT")
	}
	userSID, err := security.CurrentUserSID()
	if err != nil {
		return fmt.Errorf("dizgind heal: resolve current user SID: %w", err)
	}
	expected, err := buildExpectedTrusteeSet(userSID)
	if err != nil {
		return fmt.Errorf("dizgind heal: build expected trustee set: %w", err)
	}

	mode := "report"
	if healApplyFlag {
		mode = "apply"
	}
	fmt.Fprintf(os.Stdout, "dizgind heal (%s): scanning %d SSOT path(s)\n",
		mode, len(security.SensitiveDenyPaths(home)))

	scanned, drift, orphan, applied := 0, 0, 0, 0
	for _, p := range security.SensitiveDenyPaths(home) {
		if _, err := os.Stat(p); err != nil {
			continue // not present on host — nothing to scan
		}
		scanned++
		records, err := scanPathACEs(p, expected)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ! %s: read DACL failed: %v\n", p, err)
			continue
		}
		if len(records) == 0 {
			fmt.Fprintf(os.Stdout, "  OK %s\n", p)
			continue
		}
		fmt.Fprintf(os.Stdout, "  -- %s\n", p)
		for _, r := range records {
			label := "DRIFT "
			if r.kind == aceOrphan {
				label = "ORPHAN"
				orphan++
			} else {
				drift++
			}
			fmt.Fprintf(os.Stdout, "      %s  trustee=%s mask=0x%x\n",
				label, r.trusteeLabel, r.perms)
			if !healApplyFlag {
				continue
			}
			if !healYesFlag && !confirmRevoke(r.trusteeLabel, p) {
				fmt.Fprintln(os.Stdout, "        → skipped (no confirmation)")
				continue
			}
			if err := security.RevokePathForTrustee(p, r.trusteeSID); err != nil {
				fmt.Fprintf(os.Stderr, "        ! revoke failed: %v\n", err)
				continue
			}
			applied++
			fmt.Fprintln(os.Stdout, "        → revoked")
		}
	}

	fmt.Fprintln(os.Stdout, "")
	fmt.Fprintf(os.Stdout, "dizgind heal (%s): %d path(s) scanned, %d drift + %d orphan ACE(s) found",
		mode, scanned, drift, orphan)
	if healApplyFlag {
		fmt.Fprintf(os.Stdout, ", %d revoked", applied)
	}
	fmt.Fprintln(os.Stdout, "")
	return nil
}

// aceKind discriminates the two failure classes heal reports.
type aceKind int

const (
	aceDrift  aceKind = iota // ACCESS_ALLOWED for unexpected trustee
	aceOrphan                // ACCESS_DENIED left from a crashed session
)

// aceRecord is one classified ACE pulled off a path's DACL.
type aceRecord struct {
	kind         aceKind
	trusteeSID   *windows.SID
	trusteeLabel string
	perms        uint32
}

// scanPathACEs walks the DACL of path via GetAce + ACE_HEADER. Returns
// the subset that does not match the expected trustee set OR that is
// an ACCESS_DENIED ACE (always reported — heal runs between sessions
// when no DENY should remain on disk).
func scanPathACEs(path string, expected map[string]struct{}) ([]aceRecord, error) {
	sd, err := windows.GetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return nil, err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, err
	}
	if dacl == nil {
		return nil, nil
	}

	var out []aceRecord
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var pAce *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &pAce); err != nil {
			return out, fmt.Errorf("GetAce[%d]: %w", i, err)
		}
		if pAce == nil {
			continue
		}
		// Both ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE share the same
		// in-memory shape (Header + Mask + SidStart marker). Reinterpret
		// the SID pointer regardless of type.
		sidPtr := (*windows.SID)(unsafe.Pointer(&pAce.SidStart))
		trusteeSID, err := sidPtr.Copy()
		if err != nil {
			return out, fmt.Errorf("ACE[%d] sid copy: %w", i, err)
		}
		header := pAce.Header
		switch header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if _, ok := expected[trusteeSID.String()]; ok {
				continue // expected — not drift
			}
			out = append(out, aceRecord{
				kind:         aceDrift,
				trusteeSID:   trusteeSID,
				trusteeLabel: labelTrustee(trusteeSID),
				perms:        uint32(pAce.Mask),
			})
		case windows.ACCESS_DENIED_ACE_TYPE:
			out = append(out, aceRecord{
				kind:         aceOrphan,
				trusteeSID:   trusteeSID,
				trusteeLabel: labelTrustee(trusteeSID),
				perms:        uint32(pAce.Mask),
			})
		default:
			// SYSTEM_AUDIT / SYSTEM_ALARM etc. — heal is not in the
			// audit-policy business; skip silently.
		}
	}
	return out, nil
}

// buildExpectedTrusteeSet returns the SID strings of trustees that
// are *expected* to have allow ACEs on a sensitive path: the SYSTEM
// account, the local Administrators group, and the current user.
// Any other trustee with an allow ACE is reported as drift.
func buildExpectedTrusteeSet(userSID *windows.SID) (map[string]struct{}, error) {
	set := make(map[string]struct{}, 3)
	for _, sidType := range []windows.WELL_KNOWN_SID_TYPE{
		windows.WinLocalSystemSid,           // S-1-5-18
		windows.WinBuiltinAdministratorsSid, // S-1-5-32-544
	} {
		sid, err := windows.CreateWellKnownSid(sidType)
		if err != nil {
			return nil, fmt.Errorf("CreateWellKnownSid(%d): %w", sidType, err)
		}
		set[sid.String()] = struct{}{}
	}
	if userSID != nil {
		set[userSID.String()] = struct{}{}
	}
	return set, nil
}

// labelTrustee renders a SID as "DOMAIN\\Account" when LookupAccountSid
// resolves, falling back to the raw SID string when it does not (e.g.
// stale SID after user deletion). LookupAccountSid is best-effort —
// failure produces no error, the SID literal is the display.
func labelTrustee(sid *windows.SID) string {
	if sid == nil {
		return "(nil)"
	}
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return sid.String()
	}
	if domain == "" {
		return account + " (" + sid.String() + ")"
	}
	return domain + `\` + account + " (" + sid.String() + ")"
}

// confirmRevoke prompts the operator before each --apply revoke. Empty
// answer defaults to "no" — the conservative choice when running heal
// over an unfamiliar machine. --yes bypasses this entirely.
func confirmRevoke(trustee, path string) bool {
	fmt.Fprintf(os.Stderr, "        revoke %s on %s? [y/N]: ", trustee, path)
	var resp string
	_, _ = fmt.Scanln(&resp)
	return resp == "y" || resp == "Y" || resp == "yes" || resp == "YES"
}
