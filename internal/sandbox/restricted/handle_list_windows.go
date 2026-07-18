// SPDX-License-Identifier: MIT

//go:build windows

package restricted

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// kernel32!UpdateProcThreadAttribute is declared here because it is also
// used by the mitigation PTAL helper (mitigation_windows.go) and the box
// spawn path (box_windows.go). modKernel32 itself is declared once in
// job_windows.go; Go's package-level scoping makes the proc reachable
// from every file in the package.
var procUpdateProcThreadAttribute = modKernel32.NewProc("UpdateProcThreadAttribute")

// PROC_THREAD_ATTRIBUTE_HANDLE_LIST is the PTAL attribute key the Windows
// kernel uses to scope which inheritable handles CreateProcessW passes
// down to the child when bInheritHandles=TRUE. Without it, every handle
// in the parent's table that was opened inheritable (HANDLE_FLAG_INHERIT)
// is duplicated into the child — including ambient stdio dups,
// inherited console handles, and any third-party-library handle that
// happened to forget to clear the inherit flag.
//
// Defined in winnt.h as:
//
//	#define ProcThreadAttributeHandleList 2
//	#define PROC_THREAD_ATTRIBUTE_HANDLE_LIST \
//	    ProcThreadAttributeValue(ProcThreadAttributeHandleList, FALSE, TRUE, FALSE)
//
// The macro packs (number=2, thread=FALSE, input=TRUE, additive=FALSE)
// into the bitfield Windows expects — the encoded constant is 0x00020002.
const procThreadAttributeHandleList = 0x00020002

// applyHandleListAllowlist registers a PROC_THREAD_ATTRIBUTE_HANDLE_LIST
// entry on the supplied PTAL so the kernel restricts handle inheritance
// to exactly the three stdio handles we hand to STARTUPINFOEXW. Without
// this entry, the restricted child runs with bInheritHandles=TRUE and
// receives every inheritable handle in dizgin's process table — including
// console handles whose security descriptors do not match the child's
// token identity, which Bun's startup probe interacts with in a way
// that wedges the process before it ever emits output (carried over
// from iter5 CLAUDE-HANG-01 secondary suspect A).
//
// Inherited from iter5 Layer 2. Opt-out via DIZGIN_NO_HANDLE_LIST=1 so an
// emergency rollback is one env var away.
//
// The HANDLE array passed to UpdateProcThreadAttribute must remain
// addressable until CreateProcessAsUserW returns; callers should hold
// the returned slice alive (runtime.KeepAlive) through the spawn.
func applyHandleListAllowlist(listPtr unsafe.Pointer, handles []windows.Handle) ([]windows.Handle, error) {
	if len(handles) == 0 {
		return nil, fmt.Errorf("handle list allowlist requires ≥1 handle")
	}
	// Filter zero handles defensively — a NULL in the list trips the
	// kernel's validation pass and CreateProcess fails with
	// ERROR_INVALID_PARAMETER.
	clean := make([]windows.Handle, 0, len(handles))
	for _, h := range handles {
		if h != 0 {
			clean = append(clean, h)
		}
	}
	if len(clean) == 0 {
		return nil, fmt.Errorf("handle list allowlist: all handles were zero")
	}

	size := unsafe.Sizeof(clean[0]) * uintptr(len(clean))
	if r, _, e := procUpdateProcThreadAttribute.Call(
		uintptr(listPtr),
		0,
		uintptr(procThreadAttributeHandleList),
		uintptr(unsafe.Pointer(&clean[0])),
		size,
		0,
		0,
	); r == 0 {
		return nil, fmt.Errorf("UpdateProcThreadAttribute(HANDLE_LIST): %w", e)
	}
	return clean, nil
}
