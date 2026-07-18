// SPDX-License-Identifier: MIT

//go:build windows

package netfilter

import (
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WFP user-mode enforcement via fwpuclnt.dll.
//
// Lifecycle, per dizgin session:
//
//	Apply  → FwpmEngineOpen0 (DYNAMIC session) → FwpmGetAppIdFromFileName0
//	         → TransactionBegin → add block(v4)+block(v6) scoped to the
//	         tool's app-id → add permit per allowlisted IP → TransactionCommit.
//	         The engine handle is kept OPEN and stored in the session map.
//	Revoke → FwpmEngineClose0 on the stored handle. Because the session is
//	         DYNAMIC, every filter it added is auto-deleted by BFE the moment
//	         the handle closes. No filter-id bookkeeping, and if the daemon
//	         crashes the kernel reaps the filters when the process dies.
//
// Atomicity: every filter add happens inside one transaction. Any failure
// aborts the transaction (nothing committed) and closes the handle, so a
// half-applied filter set can never leak.
//
// Scope: the block filters carry an ALE_APP_ID == tool-binary condition,
// so ONLY the sandboxed tool's outbound connections are blocked. The host
// and every other process are untouched — without this condition the block
// would sever the whole machine's egress.
//
// GUID values are the well-known constants from <fwpmu.h> / <fwpmtypes.h>.
// Struct layouts are asserted against the documented x64 C ABI in
// wfp_layout_windows_test.go (a runnable check independent of an elevated
// host).

var (
	modFwpuclnt = windows.NewLazyDLL("fwpuclnt.dll")

	procFwpmEngineOpen0          = modFwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0         = modFwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmTransactionBegin0    = modFwpuclnt.NewProc("FwpmTransactionBegin0")
	procFwpmTransactionCommit0   = modFwpuclnt.NewProc("FwpmTransactionCommit0")
	procFwpmTransactionAbort0    = modFwpuclnt.NewProc("FwpmTransactionAbort0")
	procFwpmFilterAdd0           = modFwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmGetAppIdFromFileName = modFwpuclnt.NewProc("FwpmGetAppIdFromFileName0")
	procFwpmFreeMemory0          = modFwpuclnt.NewProc("FwpmFreeMemory0")
)

// rpcAuthnWinNT mirrors RPC_C_AUTHN_WINNT from rpcdce.h — the auth
// service WFP expects for a local engine open.
const rpcAuthnWinNT uintptr = 10

// fwpmSessionFlagDynamic (FWPM_SESSION_FLAG_DYNAMIC): filters added under
// this session are auto-deleted when the engine handle closes.
const fwpmSessionFlagDynamic = 0x00000001

// FWP_DATA_TYPE values (subset used here).
const (
	fwpUint8         uint32 = 1
	fwpUint32        uint32 = 3
	fwpByteArray16Ty uint32 = 11
	fwpByteBlobType  uint32 = 12
)

// FWP_MATCH_TYPE: FWP_MATCH_EQUAL is 0.
const fwpMatchEqual uint32 = 0

// FWP_ACTION_TYPE: BLOCK = 0x1 | TERMINATING(0x1000), PERMIT = 0x2 | TERMINATING.
const (
	fwpActionBlock  uint32 = 0x00001001
	fwpActionPermit uint32 = 0x00001002
)

// Filter weights (FWP_UINT8 weight-range index, 0..15). Higher wins
// within the sublayer, so permits (15) override the catch-all block (1).
const (
	weightBlock  uint64 = 1
	weightPermit uint64 = 15
)

// Well-known GUIDs from <fwpmu.h>.
var (
	layerALEAuthConnectV4 = windows.GUID{Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33, Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}}
	layerALEAuthConnectV6 = windows.GUID{Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc, Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}}
	condALEAppID          = windows.GUID{Data1: 0xd78e1e87, Data2: 0x8644, Data3: 0x4ea5, Data4: [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}}
	condIPRemoteAddress   = windows.GUID{Data1: 0xb235ae9a, Data2: 0x1d64, Data3: 0x49b8, Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}}
)

// ---- struct mirrors (x64 C ABI; see wfp_layout_windows_test.go) ----

type fwpByteBlob struct {
	size uint32
	_    uint32
	data *byte
}

type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

// fwpValue0 mirrors FWP_VALUE0: a 4-byte type tag + an 8-byte union.
type fwpValue0 struct {
	typ   uint32
	_     uint32
	value uint64
}

// fwpConditionValue0 mirrors FWP_CONDITION_VALUE0 — identical {type;union}
// layout to FWP_VALUE0.
type fwpConditionValue0 struct {
	typ   uint32
	_     uint32
	value uint64
}

type fwpmFilterCondition0 struct {
	fieldKey  windows.GUID
	matchType uint32
	_         uint32
	condValue fwpConditionValue0
}

type fwpmAction0 struct {
	typ        uint32
	filterType windows.GUID // union { GUID filterType; GUID calloutKey; }
}

// fwpmFilter0 mirrors FWPM_FILTER0. The provider-context union is 16 bytes
// (GUID is larger than the UINT64 rawContext alternative), modelled as a
// 2-element uint64 array; we only ever use the rawContext (low) word, left
// zero here.
type fwpmFilter0 struct {
	filterKey           windows.GUID
	displayData         fwpmDisplayData0
	flags               uint32
	_pad0               uint32
	providerKey         *windows.GUID
	providerData        fwpByteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              fwpValue0
	numFilterConditions uint32
	_pad1               uint32
	filterCondition     *fwpmFilterCondition0
	action              fwpmAction0
	_pad2               uint32
	contextUnion        [2]uint64
	reserved            *windows.GUID
	filterID            uint64
	effectiveWeight     fwpValue0
}

type fwpmSession0 struct {
	sessionKey       windows.GUID
	displayData      fwpmDisplayData0
	flags            uint32
	txnWaitTimeoutMS uint32
	processID        uint32
	_pad0            uint32
	sid              *windows.SID
	username         *uint16
	kernelMode       int32
	_pad1            uint32
}

// sessionFilters holds the open dynamic-session engine handle for a dizgin
// session. Closing it auto-deletes the session's filters.
type sessionFilters struct {
	engine uintptr
}

var sessions sync.Map // sessionID(string) -> *sessionFilters

// Apply installs the WFP block+allowlist filter set for one dizgin session,
// scoped to the appPath binary. allowlist is the raw profile list
// (hostnames / IPs); it is resolved here. Returns a human-readable
// summary line on success (for the audit/advisory log) or an error — on
// error nothing is committed and no handle is leaked, so the caller
// degrades to advisory cleanly.
func Apply(sessionID, appPath string, allowlist []string) (string, error) {
	if sessionID == "" || appPath == "" {
		return "", fmt.Errorf("netfilter: sessionID and appPath are required")
	}
	if _, dup := sessions.Load(sessionID); dup {
		return "", fmt.Errorf("netfilter: session %q already has active filters", sessionID)
	}

	resolved := ResolveAllowlist(allowlist, nil)

	if err := procFwpmEngineOpen0.Find(); err != nil {
		return "", fmt.Errorf("netfilter: fwpuclnt.dll not available: %w", err)
	}

	engine, err := openDynamicEngine()
	if err != nil {
		return "", err
	}

	appBlob, err := getAppID(appPath)
	if err != nil {
		_ = closeEngine(engine)
		return "", err
	}
	defer freeWFPMemory(unsafe.Pointer(appBlob))

	if err := transactionBegin(engine); err != nil {
		_ = closeEngine(engine)
		return "", err
	}

	addErr := addAllFilters(engine, appBlob, resolved)
	if addErr != nil {
		_ = transactionAbort(engine)
		_ = closeEngine(engine)
		return "", addErr
	}

	if err := transactionCommit(engine); err != nil {
		_ = transactionAbort(engine)
		_ = closeEngine(engine)
		return "", err
	}

	sessions.Store(sessionID, &sessionFilters{engine: engine})

	summary := fmt.Sprintf("permit=%d (v4=%d v6=%d) skipped=%d",
		resolved.Total(), len(resolved.IPv4), len(resolved.IPv6), len(resolved.Skipped))
	return summary, nil
}

// Revoke closes the session's dynamic engine handle, which makes BFE
// auto-delete every filter the session added. Idempotent: revoking an
// unknown session is a no-op.
func Revoke(sessionID string) error {
	v, ok := sessions.LoadAndDelete(sessionID)
	if !ok {
		return nil
	}
	sf, ok := v.(*sessionFilters)
	if !ok {
		return nil
	}
	return closeEngine(sf.engine)
}

// addAllFilters adds the catch-all block (v4+v6) plus a permit per
// resolved address, all scoped to the appBlob app-id. The first failure
// aborts the whole set (caller rolls back the transaction).
//
// appBlob is the FWP_BYTE_BLOB that FwpmGetAppIdFromFileName0 allocated;
// it is C-owned (not Go-GC-managed) and stays valid until Apply's
// freeWFPMemory defer runs after commit, so the ALE_APP_ID conditions can
// safely hold its address.
func addAllFilters(engine uintptr, appBlob *fwpByteBlob, r ResolvedAllowlist) error {
	if err := addBlockFilter(engine, appBlob, &layerALEAuthConnectV4); err != nil {
		return fmt.Errorf("netfilter: add block(v4): %w", err)
	}
	if err := addBlockFilter(engine, appBlob, &layerALEAuthConnectV6); err != nil {
		return fmt.Errorf("netfilter: add block(v6): %w", err)
	}
	for _, ip := range r.IPv4 {
		if err := addPermitFilterV4(engine, appBlob, ip); err != nil {
			return fmt.Errorf("netfilter: add permit(v4): %w", err)
		}
	}
	for i := range r.IPv6 {
		if err := addPermitFilterV6(engine, appBlob, &r.IPv6[i]); err != nil {
			return fmt.Errorf("netfilter: add permit(v6): %w", err)
		}
	}
	return nil
}

var filterDisplayName = mustUTF16("dizgin-netfilter")

// appIDCondition builds the ALE_APP_ID == appBlob condition. The condition
// value holds a pointer to the C-owned blob (FWP_BYTE_BLOB*), which is
// what WFP expects for FWP_BYTE_BLOB_TYPE.
func appIDCondition(appBlob *fwpByteBlob) fwpmFilterCondition0 {
	return fwpmFilterCondition0{
		fieldKey:  condALEAppID,
		matchType: fwpMatchEqual,
		condValue: fwpConditionValue0{
			typ:   fwpByteBlobType,
			value: uint64(uintptr(unsafe.Pointer(appBlob))),
		},
	}
}

func addBlockFilter(engine uintptr, appBlob *fwpByteBlob, layer *windows.GUID) error {
	cond := appIDCondition(appBlob)
	f := fwpmFilter0{
		displayData:         fwpmDisplayData0{name: &filterDisplayName[0]},
		layerKey:            *layer,
		weight:              fwpValue0{typ: fwpUint8, value: weightBlock},
		numFilterConditions: 1,
		filterCondition:     &cond,
		action:              fwpmAction0{typ: fwpActionBlock},
	}
	r1, _, _ := syscall.SyscallN(procFwpmFilterAdd0.Addr(),
		engine, uintptr(unsafe.Pointer(&f)), 0, 0)
	runtime.KeepAlive(&cond)
	runtime.KeepAlive(appBlob)
	if r1 != 0 {
		return fmt.Errorf("FwpmFilterAdd0 status 0x%x", r1)
	}
	return nil
}

func addPermitFilterV4(engine uintptr, appBlob *fwpByteBlob, ip uint32) error {
	conds := [2]fwpmFilterCondition0{
		appIDCondition(appBlob),
		{
			fieldKey:  condIPRemoteAddress,
			matchType: fwpMatchEqual,
			condValue: fwpConditionValue0{typ: fwpUint32, value: uint64(ip)},
		},
	}
	f := fwpmFilter0{
		displayData:         fwpmDisplayData0{name: &filterDisplayName[0]},
		layerKey:            layerALEAuthConnectV4,
		weight:              fwpValue0{typ: fwpUint8, value: weightPermit},
		numFilterConditions: 2,
		filterCondition:     &conds[0],
		action:              fwpmAction0{typ: fwpActionPermit},
	}
	r1, _, _ := syscall.SyscallN(procFwpmFilterAdd0.Addr(),
		engine, uintptr(unsafe.Pointer(&f)), 0, 0)
	runtime.KeepAlive(&conds)
	runtime.KeepAlive(appBlob)
	if r1 != 0 {
		return fmt.Errorf("FwpmFilterAdd0 status 0x%x", r1)
	}
	return nil
}

func addPermitFilterV6(engine uintptr, appBlob *fwpByteBlob, addr *[16]byte) error {
	conds := [2]fwpmFilterCondition0{
		appIDCondition(appBlob),
		{
			fieldKey:  condIPRemoteAddress,
			matchType: fwpMatchEqual,
			condValue: fwpConditionValue0{
				typ:   fwpByteArray16Ty,
				value: uint64(uintptr(unsafe.Pointer(addr))),
			},
		},
	}
	f := fwpmFilter0{
		displayData:         fwpmDisplayData0{name: &filterDisplayName[0]},
		layerKey:            layerALEAuthConnectV6,
		weight:              fwpValue0{typ: fwpUint8, value: weightPermit},
		numFilterConditions: 2,
		filterCondition:     &conds[0],
		action:              fwpmAction0{typ: fwpActionPermit},
	}
	r1, _, _ := syscall.SyscallN(procFwpmFilterAdd0.Addr(),
		engine, uintptr(unsafe.Pointer(&f)), 0, 0)
	runtime.KeepAlive(&conds)
	runtime.KeepAlive(appBlob)
	runtime.KeepAlive(addr)
	if r1 != 0 {
		return fmt.Errorf("FwpmFilterAdd0 status 0x%x", r1)
	}
	return nil
}

func openDynamicEngine() (uintptr, error) {
	session := fwpmSession0{flags: fwpmSessionFlagDynamic}
	var engine uintptr
	r1, _, _ := syscall.SyscallN(procFwpmEngineOpen0.Addr(),
		0,             // serverName = NULL (local)
		rpcAuthnWinNT, // authnService
		0,             // authIdentity = NULL
		uintptr(unsafe.Pointer(&session)),
		uintptr(unsafe.Pointer(&engine)),
	)
	if r1 != 0 {
		return 0, fmt.Errorf("netfilter: FwpmEngineOpen0 status 0x%x", r1)
	}
	return engine, nil
}

func closeEngine(engine uintptr) error {
	if engine == 0 {
		return nil
	}
	r1, _, _ := syscall.SyscallN(procFwpmEngineClose0.Addr(), engine)
	if r1 != 0 {
		return fmt.Errorf("netfilter: FwpmEngineClose0 status 0x%x", r1)
	}
	return nil
}

func transactionBegin(engine uintptr) error {
	r1, _, _ := syscall.SyscallN(procFwpmTransactionBegin0.Addr(), engine, 0)
	if r1 != 0 {
		return fmt.Errorf("netfilter: FwpmTransactionBegin0 status 0x%x", r1)
	}
	return nil
}

func transactionCommit(engine uintptr) error {
	r1, _, _ := syscall.SyscallN(procFwpmTransactionCommit0.Addr(), engine)
	if r1 != 0 {
		return fmt.Errorf("netfilter: FwpmTransactionCommit0 status 0x%x", r1)
	}
	return nil
}

func transactionAbort(engine uintptr) error {
	r1, _, _ := syscall.SyscallN(procFwpmTransactionAbort0.Addr(), engine)
	if r1 != 0 {
		return fmt.Errorf("netfilter: FwpmTransactionAbort0 status 0x%x", r1)
	}
	return nil
}

// getAppID resolves a binary path to the FWP_BYTE_BLOB app identifier WFP
// matches ALE_APP_ID conditions against. The returned blob is C-owned and
// must be released via freeWFPMemory(unsafe.Pointer(blob)) after the
// filters are added.
func getAppID(appPath string) (*fwpByteBlob, error) {
	p, err := windows.UTF16PtrFromString(appPath)
	if err != nil {
		return nil, fmt.Errorf("netfilter: app path UTF16: %w", err)
	}
	var blobPtr *fwpByteBlob
	r1, _, _ := syscall.SyscallN(procFwpmGetAppIdFromFileName.Addr(),
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&blobPtr)),
	)
	if r1 != 0 || blobPtr == nil {
		return nil, fmt.Errorf("netfilter: FwpmGetAppIdFromFileName0 status 0x%x", r1)
	}
	return blobPtr, nil
}

func freeWFPMemory(p unsafe.Pointer) {
	if p == nil {
		return
	}
	_, _, _ = syscall.SyscallN(procFwpmFreeMemory0.Addr(), uintptr(unsafe.Pointer(&p)))
}

func mustUTF16(s string) []uint16 {
	w, err := windows.UTF16FromString(s)
	if err != nil {
		return []uint16{0}
	}
	return w
}
