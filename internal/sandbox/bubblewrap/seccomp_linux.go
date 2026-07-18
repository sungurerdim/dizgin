// SPDX-License-Identifier: MIT

//go:build linux

package bubblewrap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// seccompFilterFD creates a memfd (or temp file) containing a compiled
// seccomp-BPF deny-list filter and returns its file descriptor.
// The caller is responsible for closing the returned *os.File after
// passing the fd to bwrap.
//
// The filter uses a deny-list strategy: all syscalls are allowed by default,
// except a curated set of high-risk syscalls that are killed immediately.
// This is appropriate for AI coding tools that need broad syscall access
// (file I/O, network, process management) but must not be able to:
//   - Attach to other processes (ptrace)
//   - Load kernel modules (init_module, finit_module)
//   - Modify the filesystem namespace (mount, umount, pivot_root, chroot)
//   - Escalate privileges (setuid, setgid, setresuid, setresgid, capset)
//   - Manipulate the BPF subsystem (bpf)
//   - Create kernel keys (add_key, request_key, keyctl)
func seccompFilterFD() (*os.File, error) {
	filter, err := buildFilter()
	if err != nil {
		return nil, fmt.Errorf("seccomp: build filter: %w", err)
	}

	// Write the filter program to a temp file that bwrap can read via fd.
	f, err := os.CreateTemp("", "dizgin-seccomp-*.bpf")
	if err != nil {
		return nil, fmt.Errorf("seccomp: create temp: %w", err)
	}

	if _, err = f.Write(filter); err != nil {
		f.Close()           //nolint:errcheck
		os.Remove(f.Name()) //nolint:errcheck
		return nil, fmt.Errorf("seccomp: write filter: %w", err)
	}

	// Seek to beginning so bwrap reads from the start.
	if _, err = f.Seek(0, 0); err != nil {
		f.Close()           //nolint:errcheck
		os.Remove(f.Name()) //nolint:errcheck
		return nil, fmt.Errorf("seccomp: seek: %w", err)
	}

	return f, nil
}

// archSpec pairs an audit-arch constant with its denied syscall list.
type archSpec struct {
	goarch string
	arch   uint32
	denied []uint32
}

// archTable maps GOARCH names to BPF filter parameters.
var archTable = []archSpec{
	{goarch: "amd64", arch: auditArchX86_64, denied: deniedX86_64},
	{goarch: "arm64", arch: auditArchAarch64, denied: deniedArm64},
}

// buildFilter constructs the BPF bytecode for the deny-list seccomp filter
// appropriate for the current CPU architecture.
func buildFilter() ([]byte, error) {
	var arch uint32
	var deniedSyscalls []uint32

	found := false
	for _, spec := range archTable {
		if spec.goarch == runtime.GOARCH {
			arch = spec.arch
			deniedSyscalls = spec.denied
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("seccomp: unsupported architecture: %s", runtime.GOARCH)
	}

	// Each BPF instruction is 8 bytes: uint16 code, uint8 jt, uint8 jf, uint32 k.
	// Program layout:
	//   0: LD [4]             — load arch word (offset 4 in seccomp_data)
	//   1: JNE arch, KILL    — if wrong arch, kill
	//   2: LD [0]             — load syscall NR (offset 0 in seccomp_data)
	//   3..N: JEQ nr, KILL   — for each denied syscall, kill if match
	//   N+1: RET ALLOW
	//   N+2: RET KILL_PROCESS

	// Number of instructions:
	// 1 (arch load) + 1 (arch check) + 1 (nr load) + len(denied) * 1 (jne) + 1 (allow) + 1 (kill)
	nInstr := 3 + len(deniedSyscalls) + 2
	prog := make([]unix.SockFilter, 0, nInstr)

	// Indices of the two terminal instructions (computed after building).
	// allowIdx = nInstr - 2, killIdx = nInstr - 1.
	allowIdx := uint8(nInstr - 2)
	killIdx := uint8(nInstr - 1)

	// 0: BPF_LD | BPF_W | BPF_ABS — load architecture.
	prog = append(prog, unix.SockFilter{
		Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS,
		K:    4, // offsetof(struct seccomp_data, arch)
	})

	// 1: BPF_JMP | BPF_JEQ | BPF_K — if arch == expected, skip to next; else kill.
	// jt = 0 (fall through to LD syscall nr on match)
	// jf = index from current position to kill instruction
	prog = append(prog, unix.SockFilter{
		Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K,
		Jt:   0,
		Jf:   killIdx - 1, // jump to kill (relative from next instruction index = 2)
		K:    arch,
	})

	// 2: BPF_LD | BPF_W | BPF_ABS — load syscall number.
	prog = append(prog, unix.SockFilter{
		Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS,
		K:    0, // offsetof(struct seccomp_data, nr)
	})

	// 3..N: one JEQ per denied syscall.
	// Current instruction index starts at 3.
	// killIdx is always the last instruction.
	for i, nr := range deniedSyscalls {
		// Relative offset to kill instruction from the instruction AFTER this one.
		// kill is at absolute index killIdx.
		// This instruction is at absolute index 3 + i.
		// Next instruction is at 3 + i + 1.
		// Distance to kill = killIdx - (3 + i + 1)
		distToKill := uint8(killIdx - uint8(3+i+1))
		prog = append(prog, unix.SockFilter{
			Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K,
			Jt:   distToKill, // on match: jump to kill
			Jf:   0,          // on mismatch: fall through to next check
			K:    nr,
		})
	}

	// allowIdx: RET SECCOMP_RET_ALLOW
	prog = append(prog, unix.SockFilter{
		Code: unix.BPF_RET | unix.BPF_K,
		K:    unix.SECCOMP_RET_ALLOW,
	})

	// killIdx: RET SECCOMP_RET_KILL_PROCESS
	prog = append(prog, unix.SockFilter{
		Code: unix.BPF_RET | unix.BPF_K,
		K:    unix.SECCOMP_RET_KILL_PROCESS,
	})

	if len(prog) != nInstr {
		return nil, fmt.Errorf("seccomp: BPF program length mismatch: got %d, want %d", len(prog), nInstr)
	}

	_ = allowIdx // verified via nInstr calculation

	// Serialise as SockFprog binary: uint16 len, uint16 pad, uint32 pad, then instructions.
	// bwrap expects the raw SockFprog struct (not just the filter instructions).
	return encodeSockFprog(prog)
}

// encodeSockFprog serialises a unix.SockFprog to bytes in native byte order.
// The kernel and bwrap expect:
//
//	struct sock_fprog {
//	    unsigned short len;
//	    struct sock_filter *filter;
//	};
//
// However, bwrap reads the filter directly as a byte stream matching struct sock_fprog
// where the filter pointer is replaced by the inline filter array. bwrap uses:
//
//	prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog)
//
// where fprog.filter points to the instructions. Since we're writing to a file,
// bwrap reads it as: 2 bytes (len) + N * 8 bytes (instructions).
func encodeSockFprog(prog []unix.SockFilter) ([]byte, error) {
	if len(prog) > 0xffff {
		return nil, fmt.Errorf("seccomp: filter too long (%d instructions)", len(prog))
	}

	var buf bytes.Buffer
	order := nativeByteOrder()

	// Write len field (uint16).
	if err := binary.Write(&buf, order, uint16(len(prog))); err != nil { //nolint:gosec
		return nil, err
	}

	// Write filter instructions. Each SockFilter is {Code uint16, Jt uint8, Jf uint8, K uint32}.
	for _, f := range prog {
		if err := binary.Write(&buf, order, f.Code); err != nil {
			return nil, err
		}
		buf.WriteByte(f.Jt)
		buf.WriteByte(f.Jf)
		if err := binary.Write(&buf, order, f.K); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// nativeByteOrder returns the native byte order of the running CPU.
func nativeByteOrder() binary.ByteOrder {
	var x uint16 = 0x0102
	b := *(*[2]byte)(unsafe.Pointer(&x))
	if b[0] == 0x01 {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

// Architecture audit constants.
const (
	auditArchX86_64  = 0xc000003e // AUDIT_ARCH_X86_64
	auditArchAarch64 = 0xc00000b7 // AUDIT_ARCH_AARCH64
)

// deniedX86_64 lists the syscall numbers to block on Linux x86_64.
// Source: linux/arch/x86/entry/syscalls/syscall_64.tbl
var deniedX86_64 = []uint32{
	101, // ptrace            — process tracing / memory inspection
	154, // modify_ldt        — LDT modification
	155, // pivot_root        — change filesystem root
	161, // chroot            — change root directory
	165, // mount             — mount filesystems
	166, // umount2           — unmount filesystems
	172, // iopl              — I/O privilege level
	173, // ioperm            — I/O port permissions
	175, // init_module       — load kernel module
	176, // delete_module     — remove kernel module
	248, // add_key           — add key to kernel keyring
	249, // request_key       — look up kernel key
	250, // keyctl            — kernel keyring operations
	298, // perf_event_open   — performance monitoring
	313, // finit_module      — load module from file descriptor
	317, // seccomp           — prevent seccomp filter manipulation
	321, // bpf               — eBPF subsystem
	323, // userfaultfd       — userspace page fault handling
	// Privilege escalation
	105, // setuid
	106, // setgid
	117, // setresuid
	119, // setresgid
	122, // setreuid
	123, // setregid
	126, // capset
}

// deniedArm64 lists the syscall numbers to block on Linux arm64.
// Source: linux/include/uapi/asm-generic/unistd.h (arm64 uses generic table)
var deniedArm64 = []uint32{
	117, // ptrace
	41,  // pivot_root
	51,  // chroot
	40,  // mount
	39,  // umount2
	103, // add_key
	104, // request_key
	105, // keyctl
	241, // perf_event_open
	128, // init_module
	129, // delete_module
	273, // finit_module
	277, // seccomp
	280, // bpf
	282, // userfaultfd
	// Privilege escalation
	146, // setuid
	147, // setgid
	164, // setresuid
	165, // setresgid
	145, // setreuid
	163, // setregid
	108, // capset
}
