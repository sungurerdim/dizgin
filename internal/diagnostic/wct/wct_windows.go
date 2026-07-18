// SPDX-License-Identifier: MIT

//go:build windows

// Package wct exposes the Windows Wait Chain Traversal (WCT) API as
// a small Go surface used by dizgin's `diagnose-hang` subcommand.
//
// When a sandboxed tool hangs after a successful spawn (CPU active,
// no output, no exit — the iter5 CLAUDE-HANG-01 symptom shape), the
// question is always "what handle is the master thread blocked on?".
// WCT is the Windows-supplied answer: WaitChainGetThreadWaitChain
// walks from a hung thread to the kernel object it's waiting on,
// then to the thread that owns that object, then to whatever THAT
// thread is waiting on, and so on. For each link the API returns
// the object type (mutex, critsec, ALPC port, console message,
// event, …) and — crucially — its NAME when one is set, which is
// the breadcrumb pointing at the actual code path that owns the
// wait.
//
// Extracted to its own package in iter6 Phase 4 (previous home was
// the now-deleted appcontainer package). WCT is backend-agnostic —
// it operates on a PID — so the diagnostic surface survives the
// backend swap unchanged.
//
// Reference: Microsoft "Wait Chain Traversal" API,
// https://learn.microsoft.com/en-us/windows/win32/api/wct/
package wct

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WCT API constants from wct.h.
const (
	wctMaxNodeCount     = 16
	wctObjnameLength    = 128
	wctpGetinfoAllFlags = 7 // WCT_OUT_OF_PROC_FLAG | _COM_FLAG | _CS_FLAG
)

// WCT_OBJECT_TYPE values. Only the ones we render are named here;
// numeric values for the rest are formatted as `type-N`.
const (
	wctCriticalSectionType = 1
	wctSendMessageType     = 2
	wctMutexType           = 3
	wctAlpcType            = 4
	wctComType             = 5
	wctThreadWaitType      = 6
	wctProcessWaitType     = 7
	wctThreadType          = 8
	wctComActivationType   = 9
	wctUnknownType         = 10
	wctSocketIoType        = 11
	wctSmbIoType           = 12
)

// WCT_OBJECT_STATUS values.
const (
	wctStatusNoAccess     = 1
	wctStatusRunning      = 2
	wctStatusBlocked      = 3
	wctStatusPidOnly      = 4
	wctStatusPidOnlyRpcss = 5
	wctStatusOwned        = 6
	wctStatusNotOwned     = 7
	wctStatusAbandoned    = 8
	wctStatusUnknown      = 9
	wctStatusError        = 10
)

// waitChainNodeInfo mirrors WAITCHAIN_NODE_INFO from wct.h. The union
// is held as a flat byte array; readers reinterpret it based on
// ObjectType (lock objects → ObjectName + Timeout + Alertable;
// thread objects → ProcessId + ThreadId + WaitTime + ContextSwitches).
//
// Layout matches a 64-bit MSVC build of wct.h:
//
//	ObjectType   DWORD                                                4 bytes
//	ObjectStatus DWORD                                                4 bytes
//	union {                                                          272 bytes
//	  LockObject   { WCHAR Name[128]; LARGE_INTEGER Timeout; BOOL Alertable; }
//	  ThreadObject { DWORD ProcessId; DWORD ThreadId; DWORD WaitTime; DWORD ContextSwitches; }
//	}
//
// Total: 280 bytes.
type waitChainNodeInfo struct {
	ObjectType   uint32
	ObjectStatus uint32
	Data         [272]byte
}

type lockObjectFields struct {
	ObjectName [wctObjnameLength]uint16
	Timeout    int64
	Alertable  uint32
	_pad       uint32
}

type threadObjectFields struct {
	ProcessId       uint32
	ThreadId        uint32
	WaitTime        uint32
	ContextSwitches uint32
}

var (
	modAdvapi32                     = windows.NewLazySystemDLL("advapi32.dll")
	procOpenThreadWaitChainSession  = modAdvapi32.NewProc("OpenThreadWaitChainSession")
	procCloseThreadWaitChainSession = modAdvapi32.NewProc("CloseThreadWaitChainSession")
	procGetThreadWaitChain          = modAdvapi32.NewProc("GetThreadWaitChain")
)

// ThreadWaitChain is one thread's chain of wait dependencies, rendered
// for human consumption. dizgin's `diagnose-hang` subcommand prints these.
type ThreadWaitChain struct {
	ThreadID uint32
	Cycle    bool
	Nodes    []WaitChainNode
}

// WaitChainNode is one link in a wait chain.
type WaitChainNode struct {
	ObjectType string
	Status     string
	Name       string
	OwnerPID   uint32
	OwnerTID   uint32
	WaitMs     uint32
}

// DiagnoseHang walks every thread of pid and returns its WCT chain.
// Useful when dizgin's child has hung and we want to know "what handle
// is the busy thread blocked on?".
//
// Returns an empty slice without error when pid has no threads (it
// already exited); the caller decides whether that is a problem.
func DiagnoseHang(pid uint32) ([]ThreadWaitChain, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snap) //nolint:errcheck

	var threads []uint32
	var entry windows.ThreadEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Thread32First(snap, &entry); err != nil {
		return nil, fmt.Errorf("Thread32First: %w", err)
	}
	for {
		if entry.OwnerProcessID == pid {
			threads = append(threads, entry.ThreadID)
		}
		if err := windows.Thread32Next(snap, &entry); err != nil {
			break
		}
	}
	if len(threads) == 0 {
		return nil, nil
	}

	hSession, _, e := procOpenThreadWaitChainSession.Call(0, 0)
	if hSession == 0 {
		return nil, fmt.Errorf("OpenThreadWaitChainSession: %w", e)
	}
	defer procCloseThreadWaitChainSession.Call(hSession) //nolint:errcheck

	out := make([]ThreadWaitChain, 0, len(threads))
	for _, tid := range threads {
		chain, err := getChain(hSession, tid)
		if err != nil {
			continue
		}
		out = append(out, chain)
	}
	return out, nil
}

func getChain(hSession uintptr, tid uint32) (ThreadWaitChain, error) {
	nodes := make([]waitChainNodeInfo, wctMaxNodeCount)
	count := uint32(wctMaxNodeCount)
	var isCycle uint32
	r, _, e := procGetThreadWaitChain.Call(
		hSession,
		0,
		uintptr(wctpGetinfoAllFlags),
		uintptr(tid),
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&nodes[0])),
		uintptr(unsafe.Pointer(&isCycle)),
	)
	if r == 0 {
		return ThreadWaitChain{}, fmt.Errorf("GetThreadWaitChain(tid=%d): %w", tid, e)
	}
	tc := ThreadWaitChain{ThreadID: tid, Cycle: isCycle != 0}
	for i := uint32(0); i < count; i++ {
		n := decodeNode(&nodes[i])
		tc.Nodes = append(tc.Nodes, n)
	}
	return tc, nil
}

func decodeNode(n *waitChainNodeInfo) WaitChainNode {
	node := WaitChainNode{
		ObjectType: objTypeString(n.ObjectType),
		Status:     statusString(n.ObjectStatus),
	}
	switch n.ObjectType {
	case wctThreadType, wctThreadWaitType, wctProcessWaitType:
		tf := (*threadObjectFields)(unsafe.Pointer(&n.Data[0]))
		node.OwnerPID = tf.ProcessId
		node.OwnerTID = tf.ThreadId
		node.WaitMs = tf.WaitTime
	default:
		lf := (*lockObjectFields)(unsafe.Pointer(&n.Data[0]))
		node.Name = utf16NullTerm(lf.ObjectName[:])
	}
	return node
}

func utf16NullTerm(buf []uint16) string {
	end := len(buf)
	for i, c := range buf {
		if c == 0 {
			end = i
			break
		}
	}
	if end == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:end])
}

func objTypeString(t uint32) string {
	switch t {
	case wctCriticalSectionType:
		return "critsec"
	case wctSendMessageType:
		return "sendmsg"
	case wctMutexType:
		return "mutex"
	case wctAlpcType:
		return "alpc"
	case wctComType:
		return "com"
	case wctThreadWaitType:
		return "thread-wait"
	case wctProcessWaitType:
		return "process-wait"
	case wctThreadType:
		return "thread"
	case wctComActivationType:
		return "com-activation"
	case wctUnknownType:
		return "unknown"
	case wctSocketIoType:
		return "socket-io"
	case wctSmbIoType:
		return "smb-io"
	default:
		return fmt.Sprintf("type-%d", t)
	}
}

func statusString(s uint32) string {
	switch s {
	case wctStatusNoAccess:
		return "no-access"
	case wctStatusRunning:
		return "running"
	case wctStatusBlocked:
		return "blocked"
	case wctStatusPidOnly:
		return "pid-only"
	case wctStatusPidOnlyRpcss:
		return "pid-rpcss"
	case wctStatusOwned:
		return "owned"
	case wctStatusNotOwned:
		return "not-owned"
	case wctStatusAbandoned:
		return "abandoned"
	case wctStatusUnknown:
		return "unknown"
	case wctStatusError:
		return "error"
	default:
		return fmt.Sprintf("status-%d", s)
	}
}

// FormatThreadChain renders one chain in a compact table-style line
// suitable for the stderr summary. Dizgin's diagnose-hang subcommand
// calls this in a loop after invoking DiagnoseHang.
func FormatThreadChain(tc ThreadWaitChain) string {
	var sb strings.Builder
	cycle := ""
	if tc.Cycle {
		cycle = " (CYCLE)"
	}
	fmt.Fprintf(&sb, "tid=%d%s nodes=%d\n", tc.ThreadID, cycle, len(tc.Nodes))
	for i, n := range tc.Nodes {
		extra := ""
		if n.Name != "" {
			extra = fmt.Sprintf(" name=%q", n.Name)
		}
		if n.OwnerPID != 0 || n.OwnerTID != 0 {
			extra += fmt.Sprintf(" owner_pid=%d owner_tid=%d wait_ms=%d", n.OwnerPID, n.OwnerTID, n.WaitMs)
		}
		fmt.Fprintf(&sb, "  [%d] %s/%s%s\n", i, n.ObjectType, n.Status, extra)
	}
	return sb.String()
}
