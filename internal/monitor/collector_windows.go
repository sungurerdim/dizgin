// SPDX-License-Identifier: MIT

//go:build windows

package monitor

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// --- Win32 structs ---

// jobObjectBasicAccountingInformation mirrors JOBOBJECT_BASIC_ACCOUNTING_INFORMATION.
type jobObjectBasicAccountingInformation struct {
	TotalUserTime             int64
	TotalKernelTime           int64
	ThisPeriodTotalUserTime   int64
	ThisPeriodTotalKernelTime int64
	TotalPageFaultCount       uint32
	TotalProcesses            uint32
	ActiveProcesses           uint32
	TotalTerminatedProcesses  uint32
}

// ioCounters mirrors IO_COUNTERS.
type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

// jobObjectBasicAndIOAccountingInformation mirrors JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION.
type jobObjectBasicAndIOAccountingInformation struct {
	BasicInfo jobObjectBasicAccountingInformation
	IoInfo    ioCounters
}

// jobObjectExtendedLimitInformation mirrors JOBOBJECT_EXTENDED_LIMIT_INFORMATION (query mode).
type jobObjectExtendedLimitInformation struct {
	BasicLimitInformation struct {
		PerProcessUserTimeLimit int64
		PerJobUserTimeLimit     int64
		LimitFlags              uint32
		_                       [4]byte // padding on 64-bit
		MinimumWorkingSetSize   uintptr
		MaximumWorkingSetSize   uintptr
		ActiveProcessLimit      uint32
		_                       [4]byte // padding on 64-bit
		Affinity                uintptr
		PriorityClass           uint32
		SchedulingClass         uint32
	}
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

// processMemoryCountersEx mirrors PROCESS_MEMORY_COUNTERS_EX.
type processMemoryCountersEx struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
	PrivateUsage               uintptr
}

const (
	jobObjectBasicAndIOAccountingInformationClass = 8
	jobObjectExtendedLimitInformationClass        = 9
)

var procGetProcessMemoryInfo = modKernel32.NewProc("K32GetProcessMemoryInfo")

// --- CPU percentage via delta sampling ---

type cpuSample struct {
	ticks int64     // TotalUserTime + TotalKernelTime (100-ns units)
	wall  time.Time // when the sample was taken
}

var (
	cpuPrevMu sync.Mutex
	cpuPrev   = make(map[int]cpuSample)
)

// cpuPrevTTL is the idle threshold after which a cpuPrev entry is evicted.
// Two collection cycles at 10 s each → 30 s gives a comfortable margin.
const cpuPrevTTL = 30 * time.Second

// computeCPUPercent calculates CPU usage from Job Object timing data.
// Returns 0 on the first call for a given PID (no previous sample).
// Entries not updated within cpuPrevTTL are pruned on each write to prevent
// the map from growing unboundedly across short-lived sessions.
func computeCPUPercent(pid int, totalTicks100ns int64) float64 {
	now := time.Now()
	cpuPrevMu.Lock()
	// Evict stale entries before writing the new sample.
	for k, v := range cpuPrev {
		if now.Sub(v.wall) > cpuPrevTTL {
			delete(cpuPrev, k)
		}
	}
	prev, hasPrev := cpuPrev[pid]
	cpuPrev[pid] = cpuSample{ticks: totalTicks100ns, wall: now}
	cpuPrevMu.Unlock()

	if !hasPrev {
		return 0
	}
	wallDelta := now.Sub(prev.wall).Seconds()
	if wallDelta <= 0 {
		return 0
	}
	tickDelta := float64(totalTicks100ns-prev.ticks) / 1e7 // 100-ns → seconds
	return (tickDelta / wallDelta) * 100
}

// --- Toolhelp32 for process/thread enumeration ---

type processEntry32 struct {
	DefaultHeapID   uintptr
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [windows.MAX_PATH]uint16
}

const (
	th32csSnapProcess = 0x00000002
)

var (
	modKernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procCreateToolhelp32Snapshot = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = modKernel32.NewProc("Process32FirstW")
	procProcess32NextW           = modKernel32.NewProc("Process32NextW")
	procGetProcessHandleCount    = modKernel32.NewProc("GetProcessHandleCount")
)

func collect(opts CollectOpts) (Metrics, error) {
	var m Metrics

	// --- Basic level: Job Object accounting ---
	if opts.JobHandle != 0 {
		if err := collectJobObjectBasic(opts.JobHandle, &m); err != nil {
			return m, fmt.Errorf("monitor: job object basic: %w", err)
		}
	} else {
		// No job object — use process memory info directly.
		collectProcessBasic(opts.PID, &m)
	}

	if opts.Level == LevelBasic {
		return m, nil
	}

	// --- Detailed level ---
	if opts.JobHandle != 0 {
		collectJobObjectIO(opts.JobHandle, &m)
	}
	if opts.TempDir != "" {
		m.DiskUsageBytes = dirSize(opts.TempDir)
	}
	if !opts.StartTime.IsZero() {
		m.Uptime = time.Since(opts.StartTime)
	}

	if opts.Level == LevelDetailed {
		return m, nil
	}

	// --- Full level ---
	collectProcessTree(opts.PID, &m)
	collectHandleCount(opts.PID, &m)

	return m, nil
}

// collectJobObjectBasic queries memory, process counts, and CPU from the job object.
func collectJobObjectBasic(jobHandle uintptr, m *Metrics) error {
	var info jobObjectExtendedLimitInformation
	err := windows.QueryInformationJobObject(
		windows.Handle(jobHandle),
		jobObjectExtendedLimitInformationClass,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
		nil,
	)
	if err != nil {
		return err
	}
	m.MemoryBytes = uint64(info.PeakJobMemoryUsed)
	m.PIDs = int(info.BasicLimitInformation.ActiveProcessLimit)
	// I/O from the extended info.
	m.IOReadBytes = info.IoInfo.ReadTransferCount
	m.IOWriteBytes = info.IoInfo.WriteTransferCount

	// CPU percentage from Job Object accounting (TotalUserTime + TotalKernelTime).
	var acctInfo jobObjectBasicAndIOAccountingInformation
	acctErr := windows.QueryInformationJobObject(
		windows.Handle(jobHandle),
		jobObjectBasicAndIOAccountingInformationClass,
		uintptr(unsafe.Pointer(&acctInfo)),
		uint32(unsafe.Sizeof(acctInfo)),
		nil,
	)
	if acctErr == nil {
		totalTicks := acctInfo.BasicInfo.TotalUserTime + acctInfo.BasicInfo.TotalKernelTime
		m.CPUPercent = computeCPUPercent(int(jobHandle), totalTicks)
	}
	return nil
}

// collectJobObjectIO queries I/O and active process count from BASIC_AND_IO_ACCOUNTING.
func collectJobObjectIO(jobHandle uintptr, m *Metrics) {
	var info jobObjectBasicAndIOAccountingInformation
	err := windows.QueryInformationJobObject(
		windows.Handle(jobHandle),
		jobObjectBasicAndIOAccountingInformationClass,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
		nil,
	)
	if err != nil {
		return // query failed — leave existing values
	}
	m.IOReadBytes = info.IoInfo.ReadTransferCount
	m.IOWriteBytes = info.IoInfo.WriteTransferCount
	m.PIDs = int(info.BasicInfo.ActiveProcesses)
}

// collectProcessBasic gets memory from a single process (no job object).
func collectProcessBasic(pid int, m *Metrics) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return
	}
	defer windows.CloseHandle(h) //nolint:errcheck

	var pmc processMemoryCountersEx
	pmc.CB = uint32(unsafe.Sizeof(pmc))
	ret, _, _ := procGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&pmc)), uintptr(pmc.CB))
	if ret != 0 {
		m.MemoryBytes = uint64(pmc.WorkingSetSize)
	}
	m.PIDs = 1
}

// collectProcessTree enumerates child processes using Toolhelp32 snapshot.
func collectProcessTree(rootPID int, m *Metrics) {
	snap, _, err := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if err != nil && snap == uintptr(windows.InvalidHandle) {
		return
	}
	hSnap := windows.Handle(snap)
	defer windows.CloseHandle(hSnap) //nolint:errcheck

	var pe processEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	ret, _, _ := procProcess32FirstW.Call(uintptr(hSnap), uintptr(unsafe.Pointer(&pe)))
	if ret == 0 {
		return
	}

	// Collect all processes and build parent→children map.
	type proc struct {
		pid     uint32
		parent  uint32
		threads uint32
	}
	var procs []proc
	for {
		procs = append(procs, proc{pid: pe.ProcessID, parent: pe.ParentProcessID, threads: pe.Threads})
		pe.Size = uint32(unsafe.Sizeof(pe))
		ret, _, _ = procProcess32NextW.Call(uintptr(hSnap), uintptr(unsafe.Pointer(&pe)))
		if ret == 0 {
			break
		}
	}

	// Single-pass parent→children map, then BFS from rootPID.
	childrenOf := make(map[uint32][]uint32, len(procs))
	for _, p := range procs {
		childrenOf[p.parent] = append(childrenOf[p.parent], p.pid)
	}
	inTree := map[uint32]bool{uint32(rootPID): true}
	queue := []uint32{uint32(rootPID)}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, child := range childrenOf[cur] {
			if !inTree[child] {
				inTree[child] = true
				queue = append(queue, child)
			}
		}
	}

	var children []int
	var totalThreads int
	for _, p := range procs {
		if inTree[p.pid] {
			if p.pid != uint32(rootPID) {
				children = append(children, int(p.pid))
			}
			totalThreads += int(p.threads)
		}
	}
	m.ChildPIDs = children
	m.ThreadCount = totalThreads
	if m.PIDs == 0 {
		m.PIDs = len(children) + 1 // root + children
	}
}

// collectHandleCount gets the open handle count for the root process.
func collectHandleCount(pid int, m *Metrics) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return
	}
	defer windows.CloseHandle(h) //nolint:errcheck

	var count uint32
	ret, _, _ := procGetProcessHandleCount.Call(uintptr(h), uintptr(unsafe.Pointer(&count)))
	if ret != 0 {
		m.HandleCount = int(count)
	}
}

// dirSize walks a directory tree and sums file sizes.
// Results are cached for 60 seconds per path to avoid repeated tree walks.
var (
	dirSizeCache    = make(map[string]dirSizeCacheEntry)
	dirSizeInFlight = make(map[string]bool)
	dirSizeCacheMu  sync.Mutex
)

type dirSizeCacheEntry struct {
	size uint64
	at   time.Time
}

func dirSize(path string) uint64 {
	dirSizeCacheMu.Lock()
	if e, ok := dirSizeCache[path]; ok && time.Since(e.at) < 60*time.Second {
		dirSizeCacheMu.Unlock()
		return e.size
	}
	// Best-effort sentinel: if another goroutine is already walking this path,
	// return the last cached value (possibly stale) to avoid a duplicate walk.
	if dirSizeInFlight[path] {
		if e, ok := dirSizeCache[path]; ok {
			dirSizeCacheMu.Unlock()
			return e.size
		}
		dirSizeCacheMu.Unlock()
		return 0
	}
	dirSizeInFlight[path] = true
	dirSizeCacheMu.Unlock()

	var total uint64
	filepath.WalkDir(path, func(_ string, d os.DirEntry, err error) error { //nolint:errcheck
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err == nil {
			total += uint64(info.Size())
		}
		return nil
	})

	dirSizeCacheMu.Lock()
	delete(dirSizeInFlight, path)
	// Prune entries older than 2x the TTL (120 s) to bound cache growth.
	now := time.Now()
	for k, v := range dirSizeCache {
		if now.Sub(v.at) > 120*time.Second {
			delete(dirSizeCache, k)
		}
	}
	dirSizeCache[path] = dirSizeCacheEntry{size: total, at: now}
	dirSizeCacheMu.Unlock()
	return total
}
