//go:build windows

package net

import (
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/xtls/xray-core/common/errors"
)

const (
	tcpTableFunc    = "GetExtendedTcpTable"
	tcpTablePidConn = 4
	udpTableFunc    = "GetExtendedUdpTable"
	udpTablePid     = 1
)

var (
	getExTCPTable uintptr
	getExUDPTable uintptr

	once    sync.Once
	initErr error
)

func initWin32API() error {
	h, err := windows.LoadLibrary("iphlpapi.dll")
	if err != nil {
		return errors.New("LoadLibrary iphlpapi.dll failed").Base(err)
	}

	getExTCPTable, err = windows.GetProcAddress(h, tcpTableFunc)
	if err != nil {
		return errors.New("GetProcAddress of ", tcpTableFunc, " failed").Base(err)
	}

	getExUDPTable, err = windows.GetProcAddress(h, udpTableFunc)
	if err != nil {
		return errors.New("GetProcAddress of ", udpTableFunc, " failed").Base(err)
	}

	return nil
}

func FindProcess(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (PID int, Name string, AbsolutePath string, err error) {
	once.Do(func() {
		initErr = initWin32API()
	})
	if initErr != nil {
		return 0, "", "", initErr
	}
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
	var class int
	var fn uintptr
	switch network {
	case "tcp":
		fn = getExTCPTable
		class = tcpTablePidConn
	case "udp":
		fn = getExUDPTable
		class = udpTablePid
	default:
		panic("Unsupported network type for process lookup.")
	}
	ip := net.ParseIP(srcIP)
	port := int(srcPort)

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return 0, "", "", errors.New("invalid IP address")
	}
	addr = addr.Unmap()

	family := windows.AF_INET
	if addr.Is6() {
		family = windows.AF_INET6
	}

	buf, err := getTransportTable(fn, family, class)
	if err != nil {
		return 0, "", "", err
	}

	networkType := Network_TCP
	if network == "udp" {
		networkType = Network_UDP
	}
	familyType := AddressFamilyIPv4
	if addr.Is6() {
		familyType = AddressFamilyIPv6
	}
	s := newSearcher(networkType, familyType)

	var destAddr netip.Addr
	if destIP != "" {
		if ip := net.ParseIP(destIP); ip != nil {
			if addr, ok := netip.AddrFromSlice(ip); ok {
				destAddr = addr.Unmap()
			}
		}
	}

	pid, err := s.Search(buf, addr, uint16(port), destAddr, destPort)
	if err != nil {
		return 0, "", "", err
	}
	NameWithPath, err := getExecPathFromPID(pid)
	NameWithPath = filepath.ToSlash(NameWithPath)

	// drop .exe and path
	nameSplit := strings.Split(NameWithPath, "/")
	procName := nameSplit[len(nameSplit)-1]
	procName = strings.TrimSuffix(procName, ".exe")
	return int(pid), procName, NameWithPath, err
}

func getTransportTable(fn uintptr, family int, class int) ([]byte, error) {
	for size, buf := uint32(8), make([]byte, 8); ; {
		ptr := unsafe.Pointer(&buf[0])
		err, _, _ := syscall.Syscall6(fn, 6, uintptr(ptr), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), uintptr(class), 0)

		switch err {
		case 0:
			return buf, nil
		case uintptr(syscall.ERROR_INSUFFICIENT_BUFFER):
			buf = make([]byte, size)
		default:
			return nil, errors.New("syscall error: ", int(err))
		}
	}
}

func getExecPathFromPID(pid uint32) (string, error) {
	// kernel process starts with a colon in order to distinguish with normal processes
	switch pid {
	case 0:
		// reserved pid for system idle process
		return ":System Idle Process", nil
	case 4:
		// reserved pid for windows kernel image
		return ":System", nil
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, syscall.MAX_LONG_PATH)
	size := uint32(len(buf))
	err = windows.QueryFullProcessImageName(h, 0, &buf[0], &size)
	if err != nil {
		return "", err
	}
	return syscall.UTF16ToString(buf[:size]), nil
}
