//go:build darwin

package net

import (
	"bytes"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/xtls/xray-core/common/errors"
)

const (
	darwinProcPIDListFDs      = 1
	darwinProcPIDFDSocketInfo = 3
	darwinProcFDTypeSocket    = 2
	darwinProcFDInfoSize      = 8
	darwinSocketFDInfoSize    = 792
	darwinSocketFDInfoPSIOff  = 24
	darwinSocketInfoProtoOff  = darwinSocketFDInfoPSIOff + 156
	darwinSocketInfoFamilyOff = darwinSocketFDInfoPSIOff + 160
	darwinSocketInfoKindOff   = darwinSocketFDInfoPSIOff + 232
	darwinSocketInfoInSockOff = darwinSocketFDInfoPSIOff + 240
	darwinInSockInfoFPortOff  = darwinSocketInfoInSockOff
	darwinInSockInfoLPortOff  = darwinSocketInfoInSockOff + 4
	darwinInSockInfoVFlagOff  = darwinSocketInfoInSockOff + 24
	darwinInSockInfoFAddrOff  = darwinSocketInfoInSockOff + 32
	darwinInSockInfoLAddrOff  = darwinSocketInfoInSockOff + 48
	darwinInSockInfoSize      = 80
	darwinInSockInfoIPv4      = 0x1
	darwinInSockInfoIPv6      = 0x2
	darwinSockInfoIN          = 1
	darwinSockInfoTCP         = 2
)

type darwinSocketMatchLevel int

const (
	darwinSocketNoMatch darwinSocketMatchLevel = iota
	darwinSocketPortMatch
	darwinSocketRemoteMatch
	darwinSocketLocalMatch
	darwinSocketExactMatch
)

func FindProcess(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (PID int, Name string, AbsolutePath string, err error) {
	isLocal, err := IsLocal(net.ParseIP(srcIP))
	if err != nil {
		return 0, "", "", errors.New("failed to determine if address is local: ", err)
	}
	if !isLocal {
		return 0, "", "", ErrNotLocal
	}
	if network != "tcp" && network != "udp" {
		panic("Unsupported network type for process lookup.")
	}

	srcAddr, err := netip.ParseAddr(srcIP)
	if err != nil {
		return 0, "", "", errors.New("invalid source IP address: ", srcIP)
	}
	srcAddr = srcAddr.Unmap()

	var dstAddr netip.Addr
	hasDstAddr := false
	if destIP != "" && destPort != 0 {
		dstAddr, err = netip.ParseAddr(destIP)
		if err != nil {
			return 0, "", "", errors.New("invalid destination IP address: ", destIP)
		}
		dstAddr = dstAddr.Unmap()
		hasDstAddr = true
	}

	processes, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return 0, "", "", errors.New("failed to list processes").Base(err)
	}

	var bestPID int32
	bestLevel := darwinSocketNoMatch
	ambiguousBest := false

	for _, process := range processes {
		pid := process.Proc.P_pid
		if pid <= 0 {
			continue
		}

		matchLevel, err := darwinProcessSocketMatchLevel(pid, network, srcAddr, srcPort, dstAddr, destPort, hasDstAddr)
		if err != nil || matchLevel == darwinSocketNoMatch {
			continue
		}
		if matchLevel == darwinSocketExactMatch {
			bestPID = pid
			bestLevel = matchLevel
			ambiguousBest = false
			break
		}
		if matchLevel > bestLevel {
			bestPID = pid
			bestLevel = matchLevel
			ambiguousBest = false
			continue
		}
		if matchLevel == bestLevel {
			ambiguousBest = true
		}
	}

	if bestLevel == darwinSocketNoMatch {
		return 0, "", "", errors.New("process not found for ", network, " connection from ", srcIP, ":", srcPort, " to ", destIP, ":", destPort)
	}
	if ambiguousBest {
		return 0, "", "", errors.New("ambiguous process match for ", network, " connection from ", srcIP, ":", srcPort, " to ", destIP, ":", destPort)
	}

	absPath, err := darwinProcessPath(bestPID)
	if err != nil {
		return 0, "", "", errors.New("could not get process path for PID ", bestPID, ": ", err)
	}

	absPath = filepath.ToSlash(absPath)
	return int(bestPID), filepath.Base(absPath), absPath, nil
}

func darwinProcessSocketMatchLevel(pid int32, network string, srcAddr netip.Addr, srcPort uint16, dstAddr netip.Addr, dstPort uint16, hasDstAddr bool) (darwinSocketMatchLevel, error) {
	fds, err := darwinProcessFDs(pid)
	if err != nil {
		return darwinSocketNoMatch, err
	}

	bestLevel := darwinSocketNoMatch
	for fd := 0; fd+darwinProcFDInfoSize <= len(fds); fd += darwinProcFDInfoSize {
		fdNumber := int32(darwinReadNativeUint32(fds[fd : fd+4]))
		fdType := darwinReadNativeUint32(fds[fd+4 : fd+8])
		if fdType != darwinProcFDTypeSocket {
			continue
		}

		info := make([]byte, darwinSocketFDInfoSize)
		n, err := darwinProcPIDFDInfo(pid, fdNumber, darwinProcPIDFDSocketInfo, info)
		if err != nil || n < darwinSocketInfoInSockOff+darwinInSockInfoSize {
			continue
		}
		level := darwinSocketInfoMatchLevel(info[:n], network, srcAddr, srcPort, dstAddr, dstPort, hasDstAddr)
		if level == darwinSocketExactMatch {
			return level, nil
		}
		if level > bestLevel {
			bestLevel = level
		}
	}

	return bestLevel, nil
}

func darwinProcessFDs(pid int32) ([]byte, error) {
	n, err := darwinProcPIDInfo(pid, darwinProcPIDListFDs, 0, nil)
	if err != nil {
		return nil, err
	}
	if n <= 0 {
		return nil, nil
	}

	buf := make([]byte, n)
	n, err = darwinProcPIDInfo(pid, darwinProcPIDListFDs, 0, buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func darwinSocketInfoMatchLevel(info []byte, network string, srcAddr netip.Addr, srcPort uint16, dstAddr netip.Addr, dstPort uint16, hasDstAddr bool) darwinSocketMatchLevel {
	protocol := int(darwinReadNativeUint32(info[darwinSocketInfoProtoOff : darwinSocketInfoProtoOff+4]))
	family := int(darwinReadNativeUint32(info[darwinSocketInfoFamilyOff : darwinSocketInfoFamilyOff+4]))
	kind := int(darwinReadNativeUint32(info[darwinSocketInfoKindOff : darwinSocketInfoKindOff+4]))

	switch network {
	case "tcp":
		if protocol != unix.IPPROTO_TCP || kind != darwinSockInfoTCP {
			return darwinSocketNoMatch
		}
	case "udp":
		if protocol != unix.IPPROTO_UDP || kind != darwinSockInfoIN {
			return darwinSocketNoMatch
		}
	default:
		return darwinSocketNoMatch
	}

	vflag := info[darwinInSockInfoVFlagOff]
	if srcAddr.Is4() {
		if family != unix.AF_INET || vflag&darwinInSockInfoIPv4 == 0 {
			return darwinSocketNoMatch
		}
	} else {
		if family != unix.AF_INET6 || vflag&darwinInSockInfoIPv6 == 0 {
			return darwinSocketNoMatch
		}
	}

	localPort := int32(darwinReadNativeUint32(info[darwinInSockInfoLPortOff : darwinInSockInfoLPortOff+4]))
	if !darwinPortMatches(localPort, srcPort) {
		return darwinSocketNoMatch
	}
	localAddrMatches := darwinAddrMatches(info[darwinInSockInfoLAddrOff:darwinInSockInfoLAddrOff+16], srcAddr)

	foreignAddrRaw := info[darwinInSockInfoFAddrOff : darwinInSockInfoFAddrOff+16]
	foreignPort := int32(darwinReadNativeUint32(info[darwinInSockInfoFPortOff : darwinInSockInfoFPortOff+4]))

	if !hasDstAddr {
		if localAddrMatches {
			return darwinSocketExactMatch
		}
		return darwinSocketNoMatch
	}

	remoteMatches := darwinPortMatches(foreignPort, dstPort) && darwinAddrMatches(foreignAddrRaw, dstAddr)
	if network == "udp" && darwinEndpointIsZero(foreignAddrRaw, foreignPort) && localAddrMatches {
		return darwinSocketExactMatch
	}
	switch {
	case localAddrMatches && remoteMatches:
		return darwinSocketExactMatch
	case localAddrMatches:
		return darwinSocketLocalMatch
	case remoteMatches:
		return darwinSocketRemoteMatch
	default:
		return darwinSocketPortMatch
	}
}

func darwinPortMatches(value int32, port uint16) bool {
	raw := uint16(value)
	return raw == port || darwinNtohs(raw) == port
}

func darwinNtohs(value uint16) uint16 {
	return value<<8 | value>>8
}

func darwinAddrMatches(raw []byte, addr netip.Addr) bool {
	if addr.Is4() {
		ip := addr.As4()
		return bytes.Equal(raw[12:16], ip[:])
	}
	ip := addr.As16()
	return bytes.Equal(raw, ip[:])
}

func darwinEndpointIsZero(rawAddr []byte, port int32) bool {
	return uint32(port) == 0 && bytes.Equal(rawAddr, make([]byte, 16))
}

func darwinReadNativeUint32(b []byte) uint32 {
	return *(*uint32)(unsafe.Pointer(&b[0]))
}

func darwinProcessPath(pid int32) (string, error) {
	buf := make([]byte, unix.PathMax)
	n, err := darwinProcPIDPath(pid, buf)
	if err != nil {
		return "", err
	}
	if n <= 0 {
		return "", errors.New("empty process path")
	}
	return strings.TrimRight(string(buf[:n]), "\x00"), nil
}

func darwinProcPIDInfo(pid int32, flavor int, arg uint64, buf []byte) (int, error) {
	var ptr unsafe.Pointer
	if len(buf) > 0 {
		ptr = unsafe.Pointer(&buf[0])
	}

	r0, _, errno := syscall_syscall6(libc_proc_pidinfo_trampoline_addr, uintptr(pid), uintptr(flavor), uintptr(arg), uintptr(ptr), uintptr(len(buf)), 0)
	if errno != 0 {
		return 0, errno
	}
	return int(r0), nil
}

func darwinProcPIDFDInfo(pid int32, fd int32, flavor int, buf []byte) (int, error) {
	var ptr unsafe.Pointer
	if len(buf) > 0 {
		ptr = unsafe.Pointer(&buf[0])
	}

	r0, _, errno := syscall_syscall6(libc_proc_pidfdinfo_trampoline_addr, uintptr(pid), uintptr(fd), uintptr(flavor), uintptr(ptr), uintptr(len(buf)), 0)
	if errno != 0 {
		return 0, errno
	}
	return int(r0), nil
}

func darwinProcPIDPath(pid int32, buf []byte) (int, error) {
	r0, _, errno := syscall_syscall6(libc_proc_pidpath_trampoline_addr, uintptr(pid), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(r0), nil
}

var libc_proc_pidinfo_trampoline_addr uintptr

//go:cgo_import_dynamic libc_proc_pidinfo proc_pidinfo "/usr/lib/libproc.dylib"

var libc_proc_pidfdinfo_trampoline_addr uintptr

//go:cgo_import_dynamic libc_proc_pidfdinfo proc_pidfdinfo "/usr/lib/libproc.dylib"

var libc_proc_pidpath_trampoline_addr uintptr

//go:cgo_import_dynamic libc_proc_pidpath proc_pidpath "/usr/lib/libproc.dylib"

// Implemented in the runtime package (runtime/sys_darwin.go).
func syscall_syscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

//go:linkname syscall_syscall6 syscall.syscall6
