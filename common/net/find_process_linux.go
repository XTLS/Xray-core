//go:build linux && !android

package net

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/xtls/xray-core/common/errors"
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
	src, err := netip.ParseAddr(srcIP)
	if err != nil {
		return 0, "", "", errors.New("invalid source IP ", srcIP).Base(err)
	}
	local := netip.AddrPortFrom(src.Unmap(), srcPort)
	var remote netip.AddrPort
	if dst, err := netip.ParseAddr(destIP); err == nil && destPort != 0 {
		remote = netip.AddrPortFrom(dst.Unmap(), destPort)
	}

	pid, absPath, err := linuxProcessFinder.find(network == "udp", local, remote)
	if err != nil {
		return 0, "", "", err
	}
	return pid, absPath[strings.LastIndexByte(absPath, '/')+1:], absPath, nil
}

// linuxProcessFinder keeps what the earlier lookups learned: the process and the descriptor of each
// socket that it read, and for each process its socket descriptors and its lowest free
// descriptors. Linux gives a new descriptor the lowest free number, so a new socket of a known
// process often gets the number of a socket that the process closed or one of its lowest free
// numbers. A lookup then reads a few descriptors instead of the descriptors of all processes.
var linuxProcessFinder = &linuxFinder{
	diag:    -1,
	owners:  make(map[uint32]fdOwner),
	noOwner: make(map[uint32]time.Time),
	procs:   make(map[int]*procFDs),
	stats:   make(map[int]procStat),
	self:    os.Getpid(),
}

const (
	// procRecentLimit is the number of the processes of the last lookups. The finder reads their
	// probable descriptors first, and it keeps their descriptor directories open.
	procRecentLimit = 16
	// procFullProbeLimit is the number of the newest recent processes whose known socket
	// descriptors a lookup reads before it lists a directory.
	procFullProbeLimit = 4
	// procHotLimit is the number of the found socket descriptors that the finder keeps for a
	// process.
	procHotLimit = 8
	// procSocketLimit is the number of the lowest socket descriptors that the finder keeps for a
	// process.
	procSocketLimit = 256
	// procFreeLimit is the number of the lowest free descriptors that the finder keeps for a
	// process.
	procFreeLimit = 4
	// socketOwnerLimit bounds the socket cache: the finder clears the cache when it reaches this
	// size.
	socketOwnerLimit = 1 << 16
	// noOwnerTime is how long the finder remembers a socket without a readable process. Without
	// root, the sockets of other users have no readable process, and a search for each of their
	// connections would read all descriptors again. noOwnerLimit bounds this cache.
	noOwnerTime  = 2 * time.Second
	noOwnerLimit = 1 << 12
	// diagRetryTime is how long the finder reads /proc/net after an unexpected error of sock_diag.
	diagRetryTime = 5 * time.Second
	// fdSetLimit is the first descriptor number that an fdSet does not record.
	fdSetLimit = 1 << 20
	// fdLinkSize is the buffer size for a descriptor link. A socket link has at most 19 bytes.
	fdLinkSize = 64
)

// testHookScan is called before the read of the descriptor list of a process. The tests set it to
// count these reads.
var testHookScan func(pid int)

type linuxFinder struct {
	mu sync.Mutex

	// diag is the netlink socket of sock_diag, or -1. diagOff is true for a protocol (diagTCP or
	// diagUDP) that sock_diag cannot serve here. After another error, the finder reads /proc/net
	// until diagRetry.
	diag      int
	diagOff   [2]bool
	diagRetry time.Time
	sequence  uint32
	request   [diagRequestSize]byte
	answer    []byte
	link      [fdLinkSize]byte
	name      [64]byte
	path      [unix.PathMax]byte
	dirents   []byte

	owners  map[uint32]fdOwner
	noOwner map[uint32]time.Time
	procs   map[int]*procFDs
	// stats has the users and the /proc inodes that the current lookup read.
	stats   map[int]procStat
	recent  []int
	proxies localProxies
	self    int
}

// fdOwner is the process and the descriptor of a socket.
type fdOwner struct {
	pid, fd int32
}

// procStat is the user of a process and the inode of /proc/<pid>. ok is false if the process
// ended.
type procStat struct {
	uid   uint32
	inode uint64
	ok    bool
}

// procFDs is what the finder knows about the descriptors of one process.
type procFDs struct {
	// dir is the open directory /proc/<pid>/fd of a recent process, or -1. dirInode is its inode: a
	// new process with the same PID has a new directory with another inode.
	dir      int
	dirInode uint64
	uid      uint32
	// unreadable is true when the finder has no right to read the descriptors. procInode is then the
	// inode of /proc/<pid>. A new process with the PID, a new user, or a new inode of /proc/<pid>
	// makes the finder try again.
	unreadable bool
	procInode  uint64
	// hot has the found socket descriptors, the newest first. sockets has the socket descriptors of
	// the scans in increasing order, and free the lowest free descriptors.
	hot     []int32
	sockets []int32
	free    []int32
	// seen has the descriptor numbers of the last scan and of later reads.
	seen fdSet
}

func (f *linuxFinder) find(udp bool, local, remote netip.AddrPort) (int, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	inode, uid, err := f.socket(udp, local, remote)
	if err != nil {
		return 0, "", err
	}
	if inode == 0 {
		return 0, "", errors.New("connection for ", local, " not found")
	}
	pid, err := f.owner(inode, uid)
	if err != nil {
		return 0, "", errors.New("could not find PID for inode ", inode).Base(err)
	}
	if pid == 0 {
		return 0, "", errors.New("no process found for inode ", inode)
	}
	absPath, err := f.exePath(pid)
	if err != nil {
		return 0, "", errors.New("could not get process name for PID ", pid).Base(err)
	}
	return pid, absPath, nil
}

// socket returns the inode and the user of the socket of a connection. It returns inode 0 if no
// socket has the address. It reads /proc/net when sock_diag cannot serve the lookup.
func (f *linuxFinder) socket(udp bool, local, remote netip.AddrPort) (uint32, uint32, error) {
	protocol := diagTCP
	if udp {
		protocol = diagUDP
	}
	if !f.diagOff[protocol] && !time.Now().Before(f.diagRetry) {
		inode, uid, err := f.diagSocket(udp, local, remote)
		if err == nil {
			return inode, uid, nil
		}
		f.diagFailed(protocol, err)
	}
	return procNetSocket(udp, local)
}

// diagFailed closes the netlink socket after an error. If the kernel cannot serve the protocol, the
// finder stops using sock_diag for it, and for both protocols if it cannot use the netlink socket.
// After another error, it uses sock_diag again after diagRetryTime.
func (f *linuxFinder) diagFailed(protocol int, err error) {
	if f.diag >= 0 {
		unix.Close(f.diag)
		f.diag = -1
	}
	switch err {
	case errDiagUnsupported:
		f.diagOff[protocol] = true
	case unix.EPROTONOSUPPORT, unix.EAFNOSUPPORT, unix.EACCES, unix.EPERM:
		f.diagOff = [2]bool{true, true}
	default:
		f.diagRetry = time.Now().Add(diagRetryTime)
		errors.LogDebugInner(context.Background(), err, "process lookup reads /proc/net for ", diagRetryTime, ": sock_diag failed")
		return
	}
	errors.LogDebugInner(context.Background(), err, "process lookup reads /proc/net: sock_diag is not available")
}

// owner returns the process that has the socket with the inode, or 0. The search stops at the
// first match:
//
//  1. The socket cache, checked with one read of the descriptor.
//  2. The probable descriptors of the recent processes. For the procFullProbeLimit newest of them,
//     these are their found and known socket descriptors and their two lowest free descriptors.
//     For the other recent processes, a few of these.
//  3. All descriptors of the processes that the finder does not know yet.
//  4. A few probable descriptors of each known process that is not recent.
//  5. All descriptors of the process of the last lookup, then of the other known processes. A scan
//     reads the descriptor numbers that the process did not have at its last scan first.
//  6. All descriptors of the processes that were not readable at an earlier lookup.
//
// In steps 3 to 5, the processes of the user of the socket come before the other processes, the
// newest first. Each step skips the processes that an earlier step read completely. A socket
// without a process stays in a negative cache for noOwnerTime.
func (f *linuxFinder) owner(inode, uid uint32) (int, error) {
	defer clear(f.stats)
	if owner, ok := f.owners[inode]; ok {
		pid, fd := int(owner.pid), int(owner.fd)
		if f.readFD(pid, fd) == inode {
			f.found(pid, fd)
			return pid, nil
		}
		delete(f.owners, inode)
	}
	if until, ok := f.noOwner[inode]; ok {
		if time.Now().Before(until) {
			return 0, nil
		}
		delete(f.noOwner, inode)
	}

	for i, pid := range f.recent {
		if fd, ok := f.probe(pid, inode, i < procFullProbeLimit); ok {
			f.found(pid, fd)
			return pid, nil
		}
	}

	pids, err := f.listProcesses()
	if err != nil {
		return 0, err
	}
	f.dropEnded(pids)
	// The scans of step 3 make the unknown processes known, and a scan can mark a process as not
	// readable, so the orders of steps 4 to 6 come first. A scan can also remove a process from
	// f.recent.
	unknown := f.unknownOrder(pids, uid)
	probes := f.knownOrder(pids, uid, f.recent)
	first := slices.Clone(f.recent[:min(1, len(f.recent))])
	scans := append(first, f.knownOrder(pids, uid, first)...)
	var retries []int
	for pid, proc := range f.procs {
		if proc.unreadable {
			retries = append(retries, pid)
		}
	}
	for _, pid := range unknown {
		if fd, ok := f.scan(pid, inode, false); ok {
			f.found(pid, fd)
			return pid, nil
		}
	}
	for _, pid := range probes {
		if fd, ok := f.probe(pid, inode, false); ok {
			f.found(pid, fd)
			return pid, nil
		}
	}
	for _, pid := range scans {
		if fd, ok := f.scan(pid, inode, false); ok {
			f.found(pid, fd)
			return pid, nil
		}
	}
	for _, pid := range retries {
		if fd, ok := f.scan(pid, inode, true); ok {
			f.found(pid, fd)
			return pid, nil
		}
	}
	if len(f.noOwner) >= noOwnerLimit {
		clear(f.noOwner)
	}
	f.noOwner[inode] = time.Now().Add(noOwnerTime)
	return 0, nil
}

// dropEnded removes the processes that ended. It also removes the entries that belong to an ended
// process with the PID of a new process: an open directory of a recent process, and the mark of a
// process that was not readable.
func (f *linuxFinder) dropEnded(pids []int) {
	for pid, proc := range f.procs {
		if _, lives := slices.BinarySearch(pids, pid); !lives {
			f.forget(pid, proc)
			continue
		}
		switch {
		case proc.unreadable:
			stat := f.stat(pid)
			if !stat.ok || stat.inode != proc.procInode || stat.uid != proc.uid {
				f.forget(pid, proc)
			}
		case proc.dir >= 0:
			var stat unix.Stat_t
			if unix.Stat(procPath(pid, "fd"), &stat) != nil || stat.Ino != proc.dirInode {
				f.forget(pid, proc)
			}
		}
	}
}

// unknownOrder returns the processes that the finder does not know: first the processes of the
// user, then the other processes. In each group, the newest process comes first.
func (f *linuxFinder) unknownOrder(pids []int, uid uint32) []int {
	var order, others []int
	for _, pid := range slices.Backward(pids) {
		if _, known := f.procs[pid]; known {
			continue
		}
		if f.stat(pid).uid == uid {
			order = append(order, pid)
		} else {
			others = append(others, pid)
		}
	}
	return append(order, others...)
}

// knownOrder returns the readable known processes that skip does not have: first the processes of
// the user, then the other processes. In each group, the newest process comes first.
func (f *linuxFinder) knownOrder(pids []int, uid uint32, skip []int) []int {
	order := make([]int, 0, len(pids))
	others := make([]int, 0, len(pids))
	for _, pid := range slices.Backward(pids) {
		proc, known := f.procs[pid]
		switch {
		case !known || proc.unreadable || slices.Contains(skip, pid):
		case proc.uid == uid:
			order = append(order, pid)
		default:
			others = append(others, pid)
		}
	}
	return append(order, others...)
}

// probe reads the probable descriptors of a new socket of a known process. With full, these are its
// found socket descriptors, its two lowest free descriptors and its known socket descriptors.
// Without full, it reads only the first of each kind and the second known socket descriptor.
func (f *linuxFinder) probe(pid int, inode uint32, full bool) (int, bool) {
	proc := f.procs[pid]
	if proc == nil || proc.unreadable {
		return 0, false
	}
	hot, free, sockets := proc.hot, proc.free[:min(2, len(proc.free))], proc.sockets
	if !full {
		hot, free, sockets = hot[:min(1, len(hot))], free[:min(1, len(free))], sockets[:min(2, len(sockets))]
	}
	for _, fd := range hot {
		if f.readFD(pid, int(fd)) == inode {
			return int(fd), true
		}
	}
	for _, fd := range slices.Clone(free) {
		socket, used := f.readFDUsed(pid, int(fd))
		if !used {
			continue
		}
		proc.take(fd)
		if socket == inode {
			return int(fd), true
		}
	}
	for _, fd := range sockets {
		if !slices.Contains(hot, fd) && f.readFD(pid, int(fd)) == inode {
			return int(fd), true
		}
	}
	return 0, false
}

// scan lists the descriptors of a process and reads them: first the numbers that the process did
// not have at its last scan, then the other numbers. It skips a process that was not readable,
// except with retry.
func (f *linuxFinder) scan(pid int, inode uint32, retry bool) (int, bool) {
	proc := f.procs[pid]
	if proc != nil && proc.unreadable && !retry {
		return 0, false
	}
	if testHookScan != nil {
		testHookScan(pid)
	}
	dir, err := unix.Open(procPath(pid, "fd"), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	var numbers []int32
	if err == nil {
		defer unix.Close(dir)
		numbers, err = f.listNumbers(dir)
	}
	switch {
	case err == unix.EACCES || err == unix.EPERM:
		f.markUnreadable(pid)
		return 0, false
	case err != nil:
		// The process ended, or a limit of the finder stopped the read. The next search tries again.
		if proc != nil {
			f.forget(pid, proc)
		}
		return 0, false
	}
	if proc == nil || proc.unreadable {
		proc = f.newProc(pid)
	}
	// The directory of the scan is not a descriptor of the process when the process is the finder.
	if pid == f.self {
		numbers = slices.DeleteFunc(numbers, func(fd int32) bool { return int(fd) == dir })
	}
	previous := proc.seen
	proc.seen = newFDSet(numbers)
	proc.free = lowestFreeFDs(numbers, procFreeLimit)
	var sockets []int32
	found := -1
	for pass := range 2 {
		for _, fd := range numbers {
			if previous.has(fd) != (pass == 1) {
				continue
			}
			socket, _ := f.readLink(dir, pid, int(fd))
			if socket == 0 {
				continue
			}
			sockets = append(sockets, fd)
			if socket == inode {
				found = int(fd)
				break
			}
		}
		if found >= 0 {
			break
		}
	}
	slices.Sort(sockets)
	if found < 0 {
		// The scan read each descriptor: the list of the socket descriptors is complete.
		proc.sockets = sockets[:min(len(sockets), procSocketLimit)]
	} else {
		proc.sockets = mergeFDs(proc.sockets, sockets)
	}
	return found, found >= 0
}

// mergeFDs returns the union of two lists of descriptors in increasing order, at most
// procSocketLimit of the lowest ones.
func mergeFDs(a, b []int32) []int32 {
	merged := slices.Compact(slices.Sorted(slices.Values(append(slices.Clone(a), b...))))
	return merged[:min(len(merged), procSocketLimit)]
}

func (f *linuxFinder) newProc(pid int) *procFDs {
	proc := &procFDs{dir: -1, uid: f.stat(pid).uid}
	f.procs[pid] = proc
	return proc
}

func (f *linuxFinder) markUnreadable(pid int) {
	if proc := f.procs[pid]; proc != nil && proc.dir >= 0 {
		unix.Close(proc.dir)
	}
	f.recent = slices.DeleteFunc(f.recent, func(item int) bool { return item == pid })
	stat := f.stat(pid)
	f.procs[pid] = &procFDs{dir: -1, uid: stat.uid, unreadable: true, procInode: stat.inode}
}

// found records the descriptor of a found socket. The process becomes the first recent process.
func (f *linuxFinder) found(pid, fd int) {
	proc := f.procs[pid]
	if proc == nil || proc.unreadable {
		proc = f.newProc(pid)
	}
	proc.hot = mruPush(proc.hot, int32(fd), procHotLimit)
	if index, known := slices.BinarySearch(proc.sockets, int32(fd)); !known {
		proc.sockets = slices.Insert(proc.sockets, index, int32(fd))
		proc.sockets = proc.sockets[:min(len(proc.sockets), procSocketLimit)]
	}
	if proc.dir < 0 {
		proc.dir, proc.dirInode = openFDDir(pid)
	}
	f.recent = mruPush(f.recent, pid, procRecentLimit+1)
	if len(f.recent) > procRecentLimit {
		if old := f.procs[f.recent[procRecentLimit]]; old != nil && old.dir >= 0 {
			unix.Close(old.dir)
			old.dir = -1
		}
		f.recent = f.recent[:procRecentLimit]
	}
}

func (f *linuxFinder) forget(pid int, proc *procFDs) {
	if proc.dir >= 0 {
		unix.Close(proc.dir)
	}
	delete(f.procs, pid)
	f.recent = slices.DeleteFunc(f.recent, func(item int) bool { return item == pid })
}

// stat returns the user of a process and the inode of /proc/<pid>. It keeps the result until the
// end of the lookup.
func (f *linuxFinder) stat(pid int) procStat {
	if stat, ok := f.stats[pid]; ok {
		return stat
	}
	stat := procStat{uid: math.MaxUint32}
	var info unix.Stat_t
	if unix.Stat(procPath(pid, ""), &info) == nil {
		stat = procStat{uid: info.Uid, inode: info.Ino, ok: true}
	}
	f.stats[pid] = stat
	return stat
}

// readFD returns the socket inode of a descriptor, or 0.
func (f *linuxFinder) readFD(pid, fd int) uint32 {
	socket, _ := f.readFDUsed(pid, fd)
	return socket
}

// readFDUsed also reports whether the process has the descriptor.
func (f *linuxFinder) readFDUsed(pid, fd int) (uint32, bool) {
	dir := -1
	if proc := f.procs[pid]; proc != nil {
		dir = proc.dir
	}
	return f.readLink(dir, pid, fd)
}

// readLink reads the link of a descriptor in the directory dir, or by its path if dir is -1. It
// records a socket in the socket cache. A scan reads many links, so the read makes no allocation.
func (f *linuxFinder) readLink(dir, pid, fd int) (uint32, bool) {
	name := f.name[:0]
	if dir < 0 {
		dir = unix.AT_FDCWD
		name = append(name, "/proc/"...)
		name = strconv.AppendInt(name, int64(pid), 10)
		name = append(name, "/fd/"...)
	}
	name = strconv.AppendInt(name, int64(fd), 10)
	name = append(name, 0)
	n, _, errno := unix.Syscall6(unix.SYS_READLINKAT, uintptr(dir), uintptr(unsafe.Pointer(&name[0])),
		uintptr(unsafe.Pointer(&f.link[0])), uintptr(len(f.link)), 0, 0)
	if errno != 0 {
		return 0, false
	}
	if proc := f.procs[pid]; proc != nil {
		proc.seen.add(int32(fd))
	}
	socket := socketInode(f.link[:min(int(n), len(f.link))])
	if socket != 0 {
		if len(f.owners) >= socketOwnerLimit {
			clear(f.owners)
		}
		f.owners[socket] = fdOwner{pid: int32(pid), fd: int32(fd)}
	}
	return socket, true
}

// listNumbers returns the numeric names in an open directory: the descriptor numbers in
// /proc/<pid>/fd, or the process IDs in /proc. It reads the entries of struct linux_dirent64
// without an allocation for each name.
func (f *linuxFinder) listNumbers(dir int) ([]int32, error) {
	if f.dirents == nil {
		f.dirents = make([]byte, 32<<10)
	}
	var numbers []int32
	for {
		n, err := unix.Getdents(dir, f.dirents)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		if n <= 0 {
			return numbers, nil
		}
		for entries := f.dirents[:n]; len(entries) > 0; {
			const nameOffset = 19
			size := int(binary.NativeEndian.Uint16(entries[16:]))
			if size <= nameOffset || size > len(entries) {
				return nil, errDirent
			}
			if number, ok := parseNumberName(entries[nameOffset:size]); ok {
				numbers = append(numbers, number)
			}
			entries = entries[size:]
		}
	}
}

var errDirent = errors.New("a directory entry is not valid")

// parseNumberName returns the number of a NUL-terminated name. The entries "." and ".." and the
// names in /proc such as "self" are not numbers.
func parseNumberName(name []byte) (int32, bool) {
	var number int64
	digits := 0
	for _, char := range name {
		if char == 0 {
			break
		}
		if char < '0' || char > '9' {
			return 0, false
		}
		number = number*10 + int64(char-'0')
		if number > math.MaxInt32 {
			return 0, false
		}
		digits++
	}
	return int32(number), digits > 0
}

func (f *linuxFinder) exePath(pid int) (string, error) {
	if proc := f.procs[pid]; proc != nil && proc.dir >= 0 {
		if n, err := unix.Readlinkat(proc.dir, "../exe", f.path[:]); err == nil {
			return string(f.path[:n]), nil
		}
	}
	n, err := unix.Readlink(procPath(pid, "exe"), f.path[:])
	if err != nil {
		return "", err
	}
	return string(f.path[:n]), nil
}

// take records that a free descriptor number is in use now. The next free number replaces it.
func (p *procFDs) take(fd int32) {
	index := slices.Index(p.free, fd)
	if index < 0 {
		return
	}
	next := p.free[len(p.free)-1] + 1
	for p.seen.has(next) {
		next++
	}
	p.free = append(slices.Delete(p.free, index, index+1), next)
}

// openFDDir opens the directory /proc/<pid>/fd. It returns -1 if the open fails.
func openFDDir(pid int) (int, uint64) {
	dir, err := unix.Open(procPath(pid, "fd"), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, 0
	}
	var stat unix.Stat_t
	if err := unix.Fstat(dir, &stat); err != nil {
		unix.Close(dir)
		return -1, 0
	}
	return dir, stat.Ino
}

// listProcesses returns the process IDs in increasing order.
func (f *linuxFinder) listProcesses() ([]int, error) {
	dir, err := unix.Open("/proc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	numbers, err := f.listNumbers(dir)
	if err != nil {
		return nil, err
	}
	pids := make([]int, len(numbers))
	for i, number := range numbers {
		pids[i] = int(number)
	}
	slices.Sort(pids)
	return pids, nil
}

// socketInode returns the inode of a link "socket:[inode]", or 0. It makes no allocation.
func socketInode(link []byte) uint32 {
	const prefix = "socket:["
	if len(link) <= len(prefix)+1 || string(link[:len(prefix)]) != prefix || link[len(link)-1] != ']' {
		return 0
	}
	var inode uint64
	for _, digit := range link[len(prefix) : len(link)-1] {
		if digit < '0' || digit > '9' {
			return 0
		}
		inode = inode*10 + uint64(digit-'0')
		if inode > math.MaxUint32 {
			return 0
		}
	}
	return uint32(inode)
}

func procPath(pid int, name string) string {
	return "/proc/" + strconv.Itoa(pid) + "/" + name
}

// lowestFreeFDs returns the lowest numbers from 0 that numbers does not have, in increasing order.
// It sorts numbers.
func lowestFreeFDs(numbers []int32, limit int) []int32 {
	slices.Sort(numbers)
	free := make([]int32, 0, limit)
	next := int32(0)
	for _, number := range numbers {
		for next < number && len(free) < limit {
			free = append(free, next)
			next++
		}
		if len(free) == limit {
			return free
		}
		next = max(next, number+1)
	}
	for len(free) < limit {
		free = append(free, next)
		next++
	}
	return free
}

// fdSet is a set of descriptor numbers below fdSetLimit.
type fdSet []uint64

func newFDSet(numbers []int32) fdSet {
	var set fdSet
	for _, fd := range numbers {
		set.add(fd)
	}
	return set
}

func (s *fdSet) add(fd int32) {
	if fd < 0 || fd >= fdSetLimit {
		return
	}
	word := int(fd / 64)
	if word >= len(*s) {
		*s = append(*s, make([]uint64, word+1-len(*s))...)
	}
	(*s)[word] |= 1 << (fd % 64)
}

func (s fdSet) has(fd int32) bool {
	if fd < 0 {
		return false
	}
	word := int(fd / 64)
	return word < len(s) && s[word]&(1<<(fd%64)) != 0
}

// Lookup of a socket with netlink sock_diag. The kernel finds a socket by its addresses, without
// a read of the socket tables of /proc/net.

const (
	diagTCP = 0
	diagUDP = 1

	nlmsgHeaderSize = 16
	diagRequestSize = nlmsgHeaderSize + 56
	diagMessageSize = 72
	diagNoCookie    = math.MaxUint32
	nlmsgAlign      = 4
	// The kernel sends a list of sockets in datagrams of at most 32 KiB.
	diagAnswerSize = 32 << 10

	// The offsets in struct inet_diag_msg.
	diagState      = 1
	diagSourcePort = 4
	diagRemotePort = 6
	diagSource     = 8
	diagRemote     = 24
	diagUID        = 64
	diagInode      = 68

	// diagTCPListen is the state TCP_LISTEN.
	diagTCPListen = 10
	diagAllStates = math.MaxUint32
	// diagConnectedStates are the TCP states with a connection. A request with only these states
	// does not read the listeners.
	diagConnectedStates = 1<<1 | 1<<2 | 1<<3 | 1<<4 | 1<<5 | 1<<8 | 1<<9 | 1<<11
)

var (
	errDiagUnsupported = errors.New("sock_diag is not available")
	errDiagAnswer      = errors.New("sock_diag gave an answer that is not valid")
	errDiagNoSocket    = errors.New("no socket")
	errStaleAnswer     = errors.New("answer to an earlier request")
)

func (f *linuxFinder) openDiag() error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return err
	}
	timeout := unix.Timeval{Sec: 1}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		unix.Close(fd)
		return err
	}
	f.diag = fd
	if f.answer == nil {
		f.answer = make([]byte, diagAnswerSize)
	}
	return nil
}

func (f *linuxFinder) diagSocket(udp bool, local, remote netip.AddrPort) (uint32, uint32, error) {
	if f.diag < 0 {
		if err := f.openDiag(); err != nil {
			return 0, 0, err
		}
	}
	if udp {
		// The kernel finds the socket that gets a datagram from remote to local. A socket without
		// a connection gets the datagrams of each remote address.
		inode, uid, err := f.diagExact(unix.IPPROTO_UDP, local, remote)
		if err != errDiagNoSocket {
			return inode, uid, err
		}
		socket, err := f.diagList(unix.IPPROTO_UDP, diagAllStates, local)
		return socket.inode, socket.uid, err
	}
	for _, candidate := range f.proxies.candidates(local, remote) {
		inode, uid, err := f.diagExact(unix.IPPROTO_TCP, local, candidate)
		if err != errDiagNoSocket {
			return inode, uid, err
		}
	}
	socket, err := f.diagList(unix.IPPROTO_TCP, diagConnectedStates, local)
	if err == nil && socket.inode != 0 && socket.remote.Addr().IsLoopback() {
		f.proxies.add(socket.remote)
	}
	return socket.inode, socket.uid, err
}

// diagExact asks the kernel for the socket with the two addresses. It returns errDiagNoSocket if
// the kernel has no such socket. For TCP, the kernel can also give a listener of the local address,
// or a socket in TIME_WAIT, which has no inode: these give errDiagNoSocket too.
func (f *linuxFinder) diagExact(protocol byte, local, remote netip.AddrPort) (uint32, uint32, error) {
	family := byte(unix.AF_INET)
	if local.Addr().Is6() {
		family = unix.AF_INET6
	}
	if remote.IsValid() && remote.Addr().Is4() != local.Addr().Is4() {
		remote = netip.AddrPort{}
	}
	if protocol == unix.IPPROTO_UDP {
		// For UDP, the kernel reads the source address as the remote address (udp_dump_one).
		f.prepare(family, protocol, unix.NLM_F_REQUEST, diagAllStates, remote, local)
	} else {
		f.prepare(family, protocol, unix.NLM_F_REQUEST, diagAllStates, local, remote)
	}
	if err := f.send(); err != nil {
		return 0, 0, err
	}
	for {
		n, err := f.receive()
		if err != nil {
			return 0, 0, err
		}
		message, err := f.parse(f.answer[:n])
		switch {
		case err == errStaleAnswer:
			continue
		case err == unix.ENOENT:
			return 0, 0, errDiagNoSocket
		case err != nil:
			return 0, 0, err
		}
		inode := binary.NativeEndian.Uint32(message[diagInode:])
		if inode == 0 || protocol == unix.IPPROTO_TCP && message[diagState] == diagTCPListen {
			return 0, 0, errDiagNoSocket
		}
		return inode, binary.NativeEndian.Uint32(message[diagUID:]), nil
	}
}

type diagListEntry struct {
	remote netip.AddrPort
	inode  uint32
	uid    uint32
	exact  bool
}

// diagList asks the kernel for the sockets with the local port. The kernel has no lookup without
// the remote address. A socket with the local address is the best result, then the first socket
// without a local address. For an IPv4 address, the finder also reads the IPv6 sockets: an IPv6
// socket can use IPv4 addresses.
func (f *linuxFinder) diagList(protocol byte, states uint32, local netip.AddrPort) (diagListEntry, error) {
	families := []byte{unix.AF_INET, unix.AF_INET6}
	if local.Addr().Is6() {
		families = families[1:]
	}
	var best diagListEntry
	for i, family := range families {
		f.prepare(family, protocol, unix.NLM_F_REQUEST|unix.NLM_F_DUMP, states, netip.AddrPortFrom(netip.Addr{}, local.Port()), netip.AddrPort{})
		if err := f.send(); err != nil {
			return diagListEntry{}, err
		}
		for done := false; !done; {
			n, err := f.receive()
			if err != nil {
				return diagListEntry{}, err
			}
			done, err = f.parseList(f.answer[:n], func(message []byte) {
				best = betterDiagEntry(best, message, local)
			})
			switch {
			case err == unix.ENOENT || err == unix.EOPNOTSUPP || err == unix.EPROTONOSUPPORT:
				if i > 0 {
					// The kernel has no list of the IPv6 sockets: the IPv4 list gives the result.
					return best, nil
				}
				return diagListEntry{}, errDiagUnsupported
			case err != nil:
				return diagListEntry{}, err
			}
		}
		if best.exact {
			break
		}
	}
	return best, nil
}

// betterDiagEntry returns the better of best and the socket of a message of a list. The kernel
// filters the list by the local port, and the check of the port keeps the result correct without
// the filter.
func betterDiagEntry(best diagListEntry, message []byte, local netip.AddrPort) diagListEntry {
	inode := binary.NativeEndian.Uint32(message[diagInode:])
	if best.exact || inode == 0 || binary.BigEndian.Uint16(message[diagSourcePort:]) != local.Port() {
		return best
	}
	size := 16
	if message[0] == unix.AF_INET {
		size = 4
	}
	source, ok := netip.AddrFromSlice(message[diagSource : diagSource+size])
	if !ok {
		return best
	}
	source = source.Unmap()
	entry := diagListEntry{inode: inode, uid: binary.NativeEndian.Uint32(message[diagUID:])}
	if port := binary.BigEndian.Uint16(message[diagRemotePort:]); port != 0 {
		if remote, ok := netip.AddrFromSlice(message[diagRemote : diagRemote+size]); ok {
			entry.remote = netip.AddrPortFrom(remote.Unmap(), port)
		}
	}
	switch {
	case source == local.Addr():
		entry.exact = true
		return entry
	case best.inode == 0 && source.IsUnspecified():
		return entry
	}
	return best
}

func (f *linuxFinder) prepare(family, protocol byte, flags uint16, states uint32, source, target netip.AddrPort) {
	f.sequence++
	request := f.request[:]
	clear(request)
	binary.NativeEndian.PutUint32(request[0:], diagRequestSize)
	binary.NativeEndian.PutUint16(request[4:], unix.SOCK_DIAG_BY_FAMILY)
	binary.NativeEndian.PutUint16(request[6:], flags)
	binary.NativeEndian.PutUint32(request[8:], f.sequence)
	request[16], request[17] = family, protocol
	binary.NativeEndian.PutUint32(request[20:], states)
	binary.BigEndian.PutUint16(request[24:], source.Port())
	binary.BigEndian.PutUint16(request[26:], target.Port())
	putDiagAddress(request[28:44], family, source.Addr())
	putDiagAddress(request[44:60], family, target.Addr())
	binary.NativeEndian.PutUint32(request[64:], diagNoCookie)
	binary.NativeEndian.PutUint32(request[68:], diagNoCookie)
}

// putDiagAddress writes an address in the form of the family. An IPv6 request has an IPv4
// address in the mapped form.
func putDiagAddress(field []byte, family byte, address netip.Addr) {
	switch {
	case !address.IsValid():
	case family == unix.AF_INET6:
		bytes := address.As16()
		copy(field, bytes[:])
	default:
		bytes := address.As4()
		copy(field, bytes[:])
	}
}

func (f *linuxFinder) send() error {
	for {
		err := unix.Sendto(f.diag, f.request[:], 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
		if err != unix.EINTR {
			return err
		}
	}
}

// receive reads the next datagram of the kernel into f.answer. It ignores the datagrams of other
// senders.
func (f *linuxFinder) receive() (int, error) {
	for {
		n, from, err := unix.Recvfrom(f.diag, f.answer, 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return 0, err
		}
		if sender, ok := from.(*unix.SockaddrNetlink); ok && sender.Pid == 0 {
			return n, nil
		}
	}
}

// parse returns the struct inet_diag_msg of the answer to the last request. An NLMSG_ERROR
// answer gives its errno.
func (f *linuxFinder) parse(answer []byte) ([]byte, error) {
	if len(answer) < nlmsgHeaderSize {
		return nil, errDiagAnswer
	}
	if binary.NativeEndian.Uint32(answer[8:]) != f.sequence {
		return nil, errStaleAnswer
	}
	switch binary.NativeEndian.Uint16(answer[4:]) {
	case unix.NLMSG_ERROR:
		if len(answer) < nlmsgHeaderSize+4 {
			return nil, errDiagAnswer
		}
		if err := diagErrno(answer[nlmsgHeaderSize:]); err != nil {
			return nil, err
		}
		// An acknowledgment: the finder asks for none.
		return nil, errDiagAnswer
	case unix.SOCK_DIAG_BY_FAMILY:
		if len(answer) < nlmsgHeaderSize+diagMessageSize {
			return nil, errDiagAnswer
		}
		return answer[nlmsgHeaderSize:], nil
	}
	return nil, errDiagAnswer
}

// diagErrno returns the error in the payload of NLMSG_ERROR or NLMSG_DONE: the kernel writes a
// negative errno there. It returns nil for 0.
func diagErrno(payload []byte) error {
	if code := -int32(binary.NativeEndian.Uint32(payload)); code > 0 {
		return unix.Errno(code)
	}
	return nil
}

// parseList calls visit for each socket of one datagram of a list. It reports whether the list
// ends in the datagram. A dump that failed in the kernel ends with an errno in NLMSG_DONE.
func (f *linuxFinder) parseList(datagram []byte, visit func(message []byte)) (bool, error) {
	for len(datagram) >= nlmsgHeaderSize {
		length := int(binary.NativeEndian.Uint32(datagram))
		if length < nlmsgHeaderSize || length > len(datagram) {
			return false, errDiagAnswer
		}
		message := datagram[:length]
		datagram = datagram[min((length+nlmsgAlign-1)&^(nlmsgAlign-1), len(datagram)):]
		if binary.NativeEndian.Uint32(message[8:]) != f.sequence {
			continue
		}
		switch binary.NativeEndian.Uint16(message[4:]) {
		case unix.NLMSG_DONE:
			if len(message) >= nlmsgHeaderSize+4 {
				return true, diagErrno(message[nlmsgHeaderSize:])
			}
			return true, nil
		case unix.NLMSG_ERROR:
			if len(message) < nlmsgHeaderSize+4 {
				return false, errDiagAnswer
			}
			if err := diagErrno(message[nlmsgHeaderSize:]); err != nil {
				return false, err
			}
			return false, errDiagAnswer
		case unix.SOCK_DIAG_BY_FAMILY:
			if len(message) < nlmsgHeaderSize+diagMessageSize {
				return false, errDiagAnswer
			}
			visit(message[nlmsgHeaderSize:])
		default:
			return false, errDiagAnswer
		}
	}
	return false, nil
}

// procNetSocket reads the socket tables of /proc/net. The finder uses them if sock_diag is not
// available.
func procNetSocket(udp bool, local netip.AddrPort) (uint32, uint32, error) {
	var procFiles []string
	switch {
	case !udp && local.Addr().Is4():
		procFiles = []string{"/proc/net/tcp", "/proc/net/tcp6"}
	case !udp:
		procFiles = []string{"/proc/net/tcp6"}
	case local.Addr().Is4():
		procFiles = []string{"/proc/net/udp", "/proc/net/udp6"}
	default:
		procFiles = []string{"/proc/net/udp6", "/proc/net/udp"}
	}

	ip := net.IP(local.Addr().AsSlice())
	targetHexAddrs := []string{formatProcNetAddress(ip.To16(), Port(local.Port()))}
	if ipv4 := ip.To4(); ipv4 != nil {
		// the one above is then the IPv4-mapped IPv6 address that an IPv6 socket has it as, in the IPv6 file
		targetHexAddrs = append(targetHexAddrs, formatProcNetAddress(ipv4, Port(local.Port())))
	}

	portFallback := ""
	if udp {
		portFallback = fmt.Sprintf(":%04X", local.Port())
	}

	inode, uid, err := findInodeInFiles(procFiles, targetHexAddrs, portFallback)
	if err != nil {
		return 0, 0, errors.New("could not search in ", strings.Join(procFiles, " and ")).Base(err)
	}
	if inode == "" {
		return 0, 0, nil
	}
	value, err := strconv.ParseUint(inode, 10, 32)
	if err != nil {
		return 0, 0, errors.New("invalid inode ", inode)
	}
	return uint32(value), uid, nil
}

// formatProcNetAddress formats the 4 or 16 bytes of addr as they are: an IPv4-mapped IPv6 address stays one
func formatProcNetAddress(addr net.IP, port Port) string {
	ipBytes := []byte(addr)

	var formatted strings.Builder
	formatted.Grow(len(ipBytes)*2 + 5)
	for i := 0; i < len(ipBytes); i += 4 {
		fmt.Fprintf(&formatted, "%08X", binary.NativeEndian.Uint32(ipBytes[i:i+4]))
	}
	fmt.Fprintf(&formatted, ":%04X", uint16(port))
	return formatted.String()
}

func findInodeInFiles(filePaths []string, targetHexAddrs []string, portFallback string) (string, uint32, error) {
	onlyMatchedPort := ""
	var onlyMatchedUID uint32 = math.MaxUint32

	for i, filePath := range filePaths {
		file, err := os.Open(filePath)
		if err != nil {
			if i > 0 && os.IsNotExist(err) {
				continue
			}
			return "", 0, err
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 {
				continue
			}
			// A socket in TIME_WAIT has no inode and no process. A new socket can have the same
			// local address and port.
			if fields[9] == "0" {
				continue
			}

			localAddress := fields[1]
			if slices.Contains(targetHexAddrs, localAddress) {
				return fields[9], parseUID(fields[7]), nil
			}
			if portFallback != "" && strings.HasSuffix(localAddress, portFallback) {
				wildcardIP := strings.TrimSuffix(localAddress, portFallback)
				if (len(wildcardIP) == 8 || len(wildcardIP) == 32) && strings.Trim(wildcardIP, "0") == "" {
					onlyMatchedPort = fields[9]
					onlyMatchedUID = parseUID(fields[7])
				}
			}
		}
		if err := scanner.Err(); err != nil {
			return "", 0, err
		}
	}

	return onlyMatchedPort, onlyMatchedUID, nil
}

func parseUID(field string) uint32 {
	uid, err := strconv.ParseUint(field, 10, 32)
	if err != nil {
		return math.MaxUint32
	}
	return uint32(uid)
}
