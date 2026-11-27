//go:build windows

package net

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
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

	windowsProcessFinder.nsi = nsiGetAllParameters.Find() == nil
	windowsProcessFinder.dynamicSize = nsiTCPDynamicSize
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
	src, err := netip.ParseAddr(srcIP)
	if err != nil {
		return 0, "", "", errors.New("invalid IP address")
	}
	local := netip.AddrPortFrom(src.Unmap(), srcPort)
	var remote netip.AddrPort
	if dst, err := netip.ParseAddr(destIP); err == nil && destPort != 0 {
		remote = netip.AddrPortFrom(dst.Unmap(), destPort)
	}

	pid, NameWithPath, err := windowsProcessFinder.find(network == "udp", local, remote)
	if pid == 0 && err != nil {
		return 0, "", "", err
	}
	NameWithPath = filepath.ToSlash(NameWithPath)

	// drop .exe and path
	procName := NameWithPath[strings.LastIndexByte(NameWithPath, '/')+1:]
	procName = strings.TrimSuffix(procName, ".exe")
	return int(pid), procName, NameWithPath, err
}

// windowsProcessFinder keeps the last socket tables and the paths of the processes. With nsi.dll, a
// TCP connection with a known remote address needs no table: the system finds the connection by its
// two addresses.
var windowsProcessFinder = &windowsFinder{paths: make(map[uint32]processPath), sweepAt: pathSweepMin}

const (
	// socketTableMaxAge is the age limit of a cached socket table. Several process rules look up the
	// same connection one after another, and a new socket is not in an older table.
	socketTableMaxAge = 100 * time.Millisecond
	// The finder closes the handles of the ended processes when the path cache has sweepAt entries,
	// at least pathSweepMin, or after pathSweepInterval.
	pathSweepMin      = 64
	pathSweepInterval = 30 * time.Second
	// tcpEstablished is MIB_TCP_STATE_ESTAB. Only established connections match.
	tcpEstablished = 5
)

const (
	socketTableTCP4 = iota
	socketTableTCP6
	socketTableUDP4
	socketTableUDP6
	socketTableCount
)

type windowsFinder struct {
	mu sync.Mutex

	// nsi is true while the finder uses NsiGetAllParameters. nsiChecked has an entry for IPv4 and one
	// for IPv6: it is true after a result of the call for that family matched the TCP table. nsiError
	// tells why the finder stopped using the call.
	nsi        bool
	nsiChecked [2]bool
	nsiError   error
	key        [2 * sockaddrInetSize]byte
	// dynamicSize is the size of the dynamic part that the call accepts. static has room for a
	// larger structure than the call needs.
	dynamicSize int
	dynamic     [64]byte
	static      [2 * nsiTCPStaticSize]byte

	tables  [socketTableCount]socketTable
	proxies localProxies
	paths   map[uint32]processPath
	sweepAt int
	swept   time.Time
	image   []uint16
}

type socketTable struct {
	fetched time.Time
	buf     []byte
}

// processPath is the path of a process with an open handle of the process. Windows does not give
// the ID of the process to a new process while a handle is open, and the handle shows whether the
// process ended.
type processPath struct {
	path   string
	handle windows.Handle
}

var errSocketNotFound = errors.New("not found")

func (f *windowsFinder) find(udp bool, local, remote netip.AddrPort) (uint32, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if time.Since(f.swept) > pathSweepInterval {
		f.sweep()
	}
	pid, cached, err := f.lookup(udp, local, remote, false)
	if err != nil {
		return 0, "", err
	}
	path, err := f.path(pid)
	if err != nil && cached {
		// A cached table can name a process that ended. A new table has the current owner.
		if pid, _, err = f.lookup(udp, local, remote, true); err != nil {
			return 0, "", err
		}
		path, err = f.path(pid)
	}
	return pid, path, err
}

// lookup returns the process of a socket. cached is true for a result from a cached table. With
// fresh, the finder reads the tables again.
func (f *windowsFinder) lookup(udp bool, local, remote netip.AddrPort, fresh bool) (pid uint32, cached bool, err error) {
	if udp {
		index, family, layout := socketTableUDP4, windows.AF_INET, &udp4Row
		if local.Addr().Is6() {
			index, family, layout = socketTableUDP6, windows.AF_INET6, &udp6Row
		}
		return f.search(index, getExUDPTable, family, udpTablePid, fresh, func(table []byte, _ bool) (uint32, bool) {
			return searchUDPTable(table, layout, local)
		})
	}

	if f.nsi && !fresh {
		for _, candidate := range f.proxies.candidates(local, remote) {
			if pid, err := f.nsiTCP(local, candidate); err == nil {
				return pid, false, nil
			}
			if !f.nsi {
				break
			}
		}
	}
	index, family, layout := socketTableTCP4, windows.AF_INET, &tcp4Row
	if local.Addr().Is6() {
		index, family, layout = socketTableTCP6, windows.AF_INET6, &tcp6Row
	}
	var target netip.AddrPort
	pid, cached, err = f.search(index, getExTCPTable, family, tcpTablePidConn, fresh, func(table []byte, cached bool) (uint32, bool) {
		var found bool
		pid, target, found = searchTCPTable(table, layout, local, remote)
		// A cached row can belong to a connection that has ended since, with the same local port.
		// Its remote address must be the given one or a known local proxy.
		if found && cached && remote.IsValid() && target != remote && !slices.Contains(f.proxies, target) {
			return 0, false
		}
		return pid, found
	})
	if err == nil && target != remote && target.Addr().IsLoopback() {
		f.proxies.add(target)
	}
	return pid, cached, err
}

// search searches the cached table first. It reads the table again if the cached table is old,
// has no row for the socket, or with fresh. match gets whether the table is the cached one.
func (f *windowsFinder) search(index int, fn uintptr, family, class int, fresh bool, match func(table []byte, cached bool) (uint32, bool)) (uint32, bool, error) {
	table := &f.tables[index]
	if !fresh && time.Since(table.fetched) < socketTableMaxAge {
		if pid, ok := match(table.buf, true); ok {
			return pid, true, nil
		}
	}
	buf, err := readSocketTable(fn, family, class, table.buf)
	if err != nil {
		return 0, false, err
	}
	table.buf, table.fetched = buf, time.Now()
	if pid, ok := match(buf, false); ok {
		return pid, false, nil
	}
	return 0, false, errSocketNotFound
}

// readSocketTable reads a socket table into buf. It keeps the buffer for the next read: one call
// reads the table when the buffer is large enough, and a call with a small buffer only gets the
// size of the table.
func readSocketTable(fn uintptr, family, class int, buf []byte) ([]byte, error) {
	for {
		size := uint32(len(buf))
		var ptr unsafe.Pointer
		if len(buf) > 0 {
			ptr = unsafe.Pointer(&buf[0])
		}
		r, _, _ := syscall.Syscall6(fn, 6, uintptr(ptr), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), uintptr(class), 0)
		switch windows.Errno(r) {
		case windows.ERROR_SUCCESS:
			return buf, nil
		case windows.ERROR_INSUFFICIENT_BUFFER:
			buf = make([]byte, size+size/4+64)
		default:
			return nil, errors.New("syscall error: ", int(r))
		}
	}
}

// iphlpapi.dll, which has GetExtendedTcpTable, imports NsiAllocateAndGetTable and
// NsiGetAllParameters of nsi.dll, the network store interface. NsiGetAllParameters finds one TCP
// connection by its two addresses: the key is two SOCKADDR_INET values, the dynamic part has the
// state at offset 0, and the static part has the process ID at offset 12. The size of the dynamic
// part depends on the build: 20 bytes on Windows 10 22H2 and 24 on Windows 11. The function is not
// documented. The finder compares a result with the TCP table before it uses the call, and it reads
// only the tables after a mismatch or an unexpected status code.
var nsiGetAllParameters = windows.NewLazySystemDLL("nsi.dll").NewProc("NsiGetAllParameters")

const (
	sockaddrInetSize = 28
	// nsiTCPDynamicSize is the first size of the dynamic part that the finder tries.
	nsiTCPDynamicSize = 20
	nsiTCPStaticSize  = 32
	nsiTCPStaticPID   = 12
	// nsiTCPConnections is the NSI object of the TCP connections.
	nsiTCPConnections = 3
	// nsiActiveStore is the store of the current values.
	nsiActiveStore = 1
)

// npiModuleID is NPI_MODULEID.
type npiModuleID struct {
	length     uint16
	moduleType uint32
	guid       windows.GUID
}

// nsiTCPModule is NPI_MS_TCP_MODULEID.
var nsiTCPModule = npiModuleID{
	length:     uint16(unsafe.Sizeof(npiModuleID{})),
	moduleType: 1,
	guid:       windows.GUID{Data1: 0xeb004a03, Data2: 0x9b1a, Data3: 0x11d4, Data4: [8]byte{0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xbc}},
}

// errNSIMismatch means that NsiGetAllParameters and the TCP table gave different processes for a
// connection.
var errNSIMismatch = errors.New("NsiGetAllParameters and the TCP table gave different processes")

// nsiTCP returns the process of the established TCP connection with the two addresses, or
// errSocketNotFound.
func (f *windowsFinder) nsiTCP(local, remote netip.AddrPort) (uint32, error) {
	putSockaddrInet(f.key[:sockaddrInetSize], local)
	putSockaddrInet(f.key[sockaddrInetSize:], remote)
	clear(f.dynamic[:])
	clear(f.static[:])
	for {
		r, _, _ := nsiGetAllParameters.Call(nsiActiveStore, uintptr(unsafe.Pointer(&nsiTCPModule)), nsiTCPConnections,
			uintptr(unsafe.Pointer(&f.key[0])), uintptr(len(f.key)), 0, 0,
			uintptr(unsafe.Pointer(&f.dynamic[0])), uintptr(f.dynamicSize),
			uintptr(unsafe.Pointer(&f.static[0])), nsiTCPStaticSize)
		switch status := windows.Errno(r); status {
		case windows.ERROR_SUCCESS:
		case windows.ERROR_NOT_FOUND:
			return 0, errSocketNotFound
		case windows.ERROR_INSUFFICIENT_BUFFER:
			if f.dynamicSize < len(f.dynamic) {
				f.dynamicSize += 4
				continue
			}
			f.stopNSI(status)
			return 0, errSocketNotFound
		default:
			f.stopNSI(status)
			return 0, errSocketNotFound
		}
		break
	}
	state := binary.LittleEndian.Uint32(f.dynamic[:])
	pid := binary.LittleEndian.Uint32(f.static[nsiTCPStaticPID:])
	if state != tcpEstablished || pid == 0 {
		return 0, errSocketNotFound
	}
	if !f.nsiChecked[nsiFamily(local)] && !f.checkNSI(local, remote, pid) {
		return 0, errSocketNotFound
	}
	return pid, nil
}

// nsiFamily returns the index of the address family of an address in nsiChecked.
func nsiFamily(address netip.AddrPort) int {
	if address.Addr().Is6() {
		return 1
	}
	return 0
}

// checkNSI compares a result of NsiGetAllParameters with the row of the TCP table. It reports
// whether the finder can use the result. If the table has no row for the connection, the lookup
// uses the table, and the next result gets the check. On a mismatch, the finder stops using the
// call.
func (f *windowsFinder) checkNSI(local, remote netip.AddrPort, pid uint32) bool {
	index, family, layout := socketTableTCP4, windows.AF_INET, &tcp4Row
	if local.Addr().Is6() {
		index, family, layout = socketTableTCP6, windows.AF_INET6, &tcp6Row
	}
	buf, err := readSocketTable(getExTCPTable, family, tcpTablePidConn, f.tables[index].buf)
	if err != nil {
		return false
	}
	f.tables[index] = socketTable{fetched: time.Now(), buf: buf}
	tablePID, target, found := searchTCPTable(buf, layout, local, remote)
	switch {
	case !found || target != remote:
		return false
	case tablePID != pid:
		f.stopNSI(errNSIMismatch)
		return false
	}
	f.nsiChecked[nsiFamily(local)] = true
	return true
}

// stopNSI makes the finder read only the tables.
func (f *windowsFinder) stopNSI(err error) {
	f.nsi = false
	f.nsiError = err
	errors.LogDebugInner(context.Background(), err, "process lookup stops using NsiGetAllParameters")
}

func putSockaddrInet(b []byte, address netip.AddrPort) {
	clear(b)
	binary.BigEndian.PutUint16(b[2:], address.Port())
	if address.Addr().Is4() {
		binary.LittleEndian.PutUint16(b[0:], windows.AF_INET)
		ip := address.Addr().As4()
		copy(b[4:8], ip[:])
		return
	}
	binary.LittleEndian.PutUint16(b[0:], windows.AF_INET6)
	ip := address.Addr().As16()
	copy(b[8:24], ip[:])
}

// socketRowLayout is the layout of a row of a socket table: MIB_TCPROW_OWNER_PID,
// MIB_TCP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID or MIB_UDP6ROW_OWNER_PID. A table has the number of
// rows in its first 4 bytes. Each port is in network order in the first 2 bytes of its field.
type socketRowLayout struct {
	size, state, localAddr, localPort, remoteAddr, remotePort, pid, addrSize int
}

var (
	tcp4Row = socketRowLayout{size: 24, state: 0, localAddr: 4, localPort: 8, remoteAddr: 12, remotePort: 16, pid: 20, addrSize: 4}
	tcp6Row = socketRowLayout{size: 56, localAddr: 0, localPort: 20, remoteAddr: 24, remotePort: 44, state: 48, pid: 52, addrSize: 16}
	udp4Row = socketRowLayout{size: 12, localAddr: 0, localPort: 4, pid: 8, addrSize: 4}
	udp6Row = socketRowLayout{size: 28, localAddr: 0, localPort: 20, pid: 24, addrSize: 16}
)

// tableRows returns the number of the complete rows of a table and the bytes of the rows.
func tableRows(table []byte, layout *socketRowLayout) (int, []byte) {
	if len(table) < 4 {
		return 0, nil
	}
	count := int(binary.LittleEndian.Uint32(table))
	return min(count, (len(table)-4)/layout.size), table[4:]
}

// searchTCPTable returns the process of the established TCP connection with the local address. A
// row with the remote address too is the best result. target is the remote address of the result.
func searchTCPTable(table []byte, layout *socketRowLayout, local, remote netip.AddrPort) (pid uint32, target netip.AddrPort, found bool) {
	count, data := tableRows(table, layout)
	localIP := local.Addr().AsSlice()
	remoteIP := remote.Addr().AsSlice()
	for i := range count {
		row := data[i*layout.size : (i+1)*layout.size]
		if binary.BigEndian.Uint16(row[layout.localPort:]) != local.Port() ||
			binary.LittleEndian.Uint32(row[layout.state:]) != tcpEstablished ||
			string(row[layout.localAddr:layout.localAddr+layout.addrSize]) != string(localIP) {
			continue
		}
		rowPID := binary.LittleEndian.Uint32(row[layout.pid:])
		rowRemote := row[layout.remoteAddr : layout.remoteAddr+layout.addrSize]
		rowPort := binary.BigEndian.Uint16(row[layout.remotePort:])
		if rowPort == remote.Port() && string(rowRemote) == string(remoteIP) {
			return rowPID, remote, true
		}
		if !found {
			address, _ := netip.AddrFromSlice(rowRemote)
			pid, target, found = rowPID, netip.AddrPortFrom(address.Unmap(), rowPort), true
		}
	}
	return pid, target, found
}

// searchUDPTable returns the process of the first UDP socket with the local port and the local
// address or no address: windows binds an unbound socket to 0.0.0.0 or [::] at its first send.
func searchUDPTable(table []byte, layout *socketRowLayout, local netip.AddrPort) (uint32, bool) {
	count, data := tableRows(table, layout)
	localIP := local.Addr().AsSlice()
	for i := range count {
		row := data[i*layout.size : (i+1)*layout.size]
		if binary.BigEndian.Uint16(row[layout.localPort:]) != local.Port() {
			continue
		}
		address := row[layout.localAddr : layout.localAddr+layout.addrSize]
		if string(address) == string(localIP) || isZeroAddress(address) {
			return binary.LittleEndian.Uint32(row[layout.pid:]), true
		}
	}
	return 0, false
}

func isZeroAddress(address []byte) bool {
	for _, b := range address {
		if b != 0 {
			return false
		}
	}
	return true
}

// path returns the path of the program of a process. The kernel processes start with a colon.
func (f *windowsFinder) path(pid uint32) (string, error) {
	switch pid {
	case 0:
		// reserved pid for system idle process
		return ":System Idle Process", nil
	case 4:
		// reserved pid for windows kernel image
		return ":System", nil
	}
	if entry, ok := f.paths[pid]; ok {
		if !processEnded(entry.handle) {
			return entry.path, nil
		}
		windows.CloseHandle(entry.handle)
		delete(f.paths, pid)
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		// Without the right to wait for the process, the finder cannot see its end. It reads the
		// path each time.
		handle, err = windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			return "", err
		}
		defer windows.CloseHandle(handle)
		return f.imagePath(handle)
	}
	path, err := f.imagePath(handle)
	if err != nil {
		windows.CloseHandle(handle)
		return "", err
	}
	if len(f.paths) >= f.sweepAt {
		f.sweep()
	}
	f.paths[pid] = processPath{path: path, handle: handle}
	return path, nil
}

func (f *windowsFinder) imagePath(handle windows.Handle) (string, error) {
	if f.image == nil {
		f.image = make([]uint16, windows.MAX_LONG_PATH)
	}
	size := uint32(len(f.image))
	if err := windows.QueryFullProcessImageName(handle, 0, &f.image[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(f.image[:size]), nil
}

// sweep closes the handles of the ended processes. A handle keeps the process object of the kernel
// and its ID.
func (f *windowsFinder) sweep() {
	for pid, entry := range f.paths {
		if processEnded(entry.handle) {
			windows.CloseHandle(entry.handle)
			delete(f.paths, pid)
		}
	}
	f.sweepAt = max(pathSweepMin, 2*len(f.paths))
	f.swept = time.Now()
}

func processEnded(handle windows.Handle) bool {
	event, err := windows.WaitForSingleObject(handle, 0)
	return err != nil || event != uint32(windows.WAIT_TIMEOUT)
}
