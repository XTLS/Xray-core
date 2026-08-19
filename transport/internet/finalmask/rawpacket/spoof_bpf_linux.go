//go:build linux

package rawpacket

import (
	"log"
	"unsafe"

	"golang.org/x/sys/unix"
)

// sockFilter and sockFprog mirror the kernel's struct sock_filter /
// struct sock_fprog (classic BPF). SO_ATTACH_FILTER is a Linux-only
// socket option; other platforms build the stub below.
type sockFilter struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

type sockFprog struct {
	Len    uint16
	Filter *sockFilter
}

const (
	bpfLdAbs       = 0x30 // BPF_LD|BPF_B|BPF_ABS: load byte at absolute offset
	bpfJeq         = 0x15 // BPF_JMP|BPF_JEQ|BPF_K
	bpfRet         = 0x06 // BPF_RET|BPF_K
	bpfKeepAll     = 0xffffffff
	bpfDrop        = 0
	soAttachFilter = 26 // SOL_SOCKET level option (Linux)
)

// attachBPFFilter installs a filter that keeps only IPv4 packets whose
// protocol byte (offset 9) matches proto, dropping everything else in
// the kernel. Failures are logged but non-fatal: userspace already
// filters by protocol.
func attachBPFFilter(fd int, proto uint8) {
	filter := []sockFilter{
		{Code: bpfLdAbs, K: 9},                         // A = ip.proto
		{Code: bpfJeq, Jt: 1, Jf: 0, K: uint32(proto)}, // if A == proto skip the drop
		{Code: bpfRet, K: bpfDrop},                     // else drop
		{Code: bpfRet, K: bpfKeepAll},                  // keep
	}
	fprog := sockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(fd), uintptr(unix.SOL_SOCKET), uintptr(soAttachFilter),
		uintptr(unsafe.Pointer(&fprog)), unsafe.Sizeof(fprog), 0)
	if errno != 0 {
		log.Printf("[rawpacket] failed to attach BPF filter (proto %d): %v", proto, errno)
	}
}
