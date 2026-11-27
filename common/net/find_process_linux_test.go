//go:build linux && !android

package net

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	stdnet "net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestFindProcessIPv4Mapped(t *testing.T) {
	listener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peer, err := stdnet.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	// an IPv6 socket that connects to an IPv4 address, as the sockets of Java and .NET are
	for _, c := range []struct{ local, remote stdnet.Addr }{
		{&stdnet.TCPAddr{IP: stdnet.IPv6zero}, listener.Addr()},
		{&stdnet.UDPAddr{IP: stdnet.IPv6zero}, peer.LocalAddr()},
	} {
		network := c.remote.Network()
		conn, err := (&stdnet.Dialer{LocalAddr: c.local}).Dial(network, c.remote.String())
		if errors.Is(err, syscall.EAFNOSUPPORT) {
			t.Skip("no IPv6 sockets here")
		}
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		local := netip.MustParseAddrPort(conn.LocalAddr().String())
		remote := netip.MustParseAddrPort(c.remote.String())
		pid, _, _, err := FindProcess(network, "127.0.0.1", local.Port(), "127.0.0.1", remote.Port())
		if err != nil {
			t.Errorf("%s: %v", network, err)
		} else if pid != os.Getpid() {
			t.Errorf("%s: found PID %d, want %d", network, pid, os.Getpid())
		}
	}
}

// TestFindProcessUDPDualStack checks an IPv6 socket without IPV6_V6ONLY and without an address that
// sends an IPv4 datagram.
func TestFindProcessUDPDualStack(t *testing.T) {
	socket, err := stdnet.ListenPacket("udp", "[::]:0")
	if errors.Is(err, unix.EAFNOSUPPORT) {
		t.Skip("no IPv6 sockets here")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	peer, err := stdnet.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if _, err := socket.WriteTo([]byte{0}, peer.LocalAddr()); err != nil {
		t.Skip("no dual-stack sockets here: ", err)
	}
	port := socket.LocalAddr().(*stdnet.UDPAddr).Port
	wantOwnProcess(t, "udp", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: port}, peer.LocalAddr())
}

// withoutSockDiag runs test with the socket tables of /proc/net only.
func withoutSockDiag(t *testing.T, test func()) {
	f := linuxProcessFinder
	f.mu.Lock()
	off := f.diagOff
	f.diagOff = [2]bool{true, true}
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.diagOff = off
		f.mu.Unlock()
	}()
	test()
}

func TestFindProcessProcNet(t *testing.T) {
	withoutSockDiag(t, func() {
		testFindProcessTCP(t, "tcp4", "127.0.0.1:0")
		socket, err := stdnet.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer socket.Close()
		wantOwnProcess(t, "udp", socket.LocalAddr(), nil)
	})
}

// TestFindInodeInFilesSkipsTimeWait checks the /proc/net search when a socket in TIME_WAIT has the
// local address of a new connection. Linux permits this when the remote addresses differ.
func TestFindInodeInFilesSkipsTimeWait(t *testing.T) {
	const table = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:9C40 0100007F:1F90 06 00000000:00000000 03:00001770 00000000     0        0 0 3 0000000000000000
   1: 0100007F:9C40 0100007F:1F91 01 00000000:00000000 00:00000000 00000000  1000        0 52731 1 0000000000000000 20 4 30 10 -1
`
	path := filepath.Join(t.TempDir(), "tcp")
	if err := os.WriteFile(path, []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	inode, uid, err := findInodeInFiles([]string{path}, []string{"0100007F:9C40"}, "")
	if err != nil || inode != "52731" || uid != 1000 {
		t.Errorf("findInodeInFiles = %q, %d, %v, want 52731, 1000", inode, uid, err)
	}
}

// TestFindProcessTimeWait checks a connection whose local address and port are those of sockets
// in TIME_WAIT with other remote addresses, with sock_diag and with /proc/net.
func TestFindProcessTimeWait(t *testing.T) {
	local := &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1)}
	for range 8 {
		listener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		// The server closes its socket after the client: the socket of the client goes to TIME_WAIT.
		closed := make(chan struct{})
		go func() {
			defer close(closed)
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			io.Copy(io.Discard, conn)
			conn.Close()
		}()
		conn := dialFrom(t, local, listener.Addr())
		local.Port = conn.LocalAddr().(*stdnet.TCPAddr).Port
		conn.Close()
		<-closed
	}
	listener := listenTCP(t, "tcp4", "127.0.0.1:0")
	conn := dialFrom(t, local, listener.Addr())
	defer conn.Close()
	if timeWaitSockets(t, local.Port) == 0 {
		t.Skip("no socket in TIME_WAIT has the local port")
	}
	wantOwnProcess(t, "tcp", conn.LocalAddr(), conn.RemoteAddr())
	withoutSockDiag(t, func() {
		wantOwnProcess(t, "tcp", conn.LocalAddr(), conn.RemoteAddr())
	})
}

// dialFrom connects from the local address with SO_REUSEADDR: connections to different remote
// addresses can then have the same local address and port.
func dialFrom(t *testing.T, local, remote stdnet.Addr) stdnet.Conn {
	t.Helper()
	dialer := stdnet.Dialer{LocalAddr: local, Control: func(network, address string, c syscall.RawConn) error {
		var err error
		if controlErr := c.Control(func(fd uintptr) {
			err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		}); controlErr != nil {
			return controlErr
		}
		return err
	}}
	conn, err := dialer.Dial("tcp4", remote.String())
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// timeWaitSockets returns the number of IPv4 TCP sockets in TIME_WAIT with the local port. The
// server closes its socket after the client, so the test waits for the last FIN.
func timeWaitSockets(t *testing.T, port int) int {
	t.Helper()
	suffix := fmt.Sprintf(":%04X", port)
	for deadline := time.Now().Add(time.Second); ; time.Sleep(10 * time.Millisecond) {
		file, err := os.Open("/proc/net/tcp")
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		lines := bufio.NewScanner(file)
		for lines.Scan() {
			fields := strings.Fields(lines.Text())
			if len(fields) > 3 && strings.HasSuffix(fields[1], suffix) && fields[3] == "06" {
				count++
			}
		}
		file.Close()
		if count > 0 || time.Now().After(deadline) {
			return count
		}
	}
}

func addrPortOf(address stdnet.Addr) netip.AddrPort {
	return netip.MustParseAddrPort(address.String())
}

// socketInodeOf returns the inode of the socket of a connection.
func socketInodeOf(t *testing.T, conn any) uint32 {
	t.Helper()
	raw, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	var statErr error
	if err := raw.Control(func(fd uintptr) { statErr = unix.Fstat(int(fd), &stat) }); err != nil {
		t.Fatal(err)
	}
	if statErr != nil {
		t.Fatal(statErr)
	}
	return uint32(stat.Ino)
}

// TestFindProcessSockDiag checks the requests of sock_diag. The kernel finds the TCP socket of a
// connection and a UDP socket by their addresses: these lookups need no list of sockets.
func TestFindProcessSockDiag(t *testing.T) {
	f := &linuxFinder{diag: -1}
	if err := f.openDiag(); err != nil {
		t.Skip("no sock_diag here: ", err)
	}
	defer unix.Close(f.diag)

	t.Run("tcp", func(t *testing.T) {
		if _, err := f.diagList(unix.IPPROTO_TCP, diagConnectedStates, netip.MustParseAddrPort("127.0.0.1:1")); err == errDiagUnsupported {
			t.Skip("no TCP sock_diag here")
		}
		listener := listenTCP(t, "tcp4", "127.0.0.1:0")
		conn := dialTCP(t, "tcp4", listener.Addr().String())
		local, remote := addrPortOf(conn.LocalAddr()), addrPortOf(conn.RemoteAddr())
		if inode, _, err := f.diagExact(unix.IPPROTO_TCP, local, remote); err != nil || inode != socketInodeOf(t, conn) {
			t.Errorf("diagExact(%v -> %v) = %d, %v, want %d", local, remote, inode, err, socketInodeOf(t, conn))
		}
		// For a local address without a connection to the remote address, the kernel gives the
		// listener.
		if inode, _, err := f.diagExact(unix.IPPROTO_TCP, addrPortOf(listener.Addr()), netip.MustParseAddrPort("127.0.0.1:1")); err != errDiagNoSocket {
			t.Errorf("diagExact of the listener = %d, %v, want errDiagNoSocket", inode, err)
		}

		// Two connections from the same address and port: the remote address selects the socket,
		// and a local proxy matches only after the remote address.
		proxy := listenTCP(t, "tcp4", "127.0.0.1:0")
		toProxy := dialFrom(t, &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1)}, proxy.Addr())
		defer toProxy.Close()
		toListener := dialFrom(t, toProxy.LocalAddr(), listener.Addr())
		defer toListener.Close()
		f.proxies.add(addrPortOf(proxy.Addr()))
		source := addrPortOf(toProxy.LocalAddr())
		for _, c := range []struct {
			remote netip.AddrPort
			conn   stdnet.Conn
		}{
			{addrPortOf(listener.Addr()), toListener},
			{netip.MustParseAddrPort("203.0.113.1:443"), toProxy},
		} {
			if inode, _, err := f.diagSocket(false, source, c.remote); err != nil || inode != socketInodeOf(t, c.conn) {
				t.Errorf("diagSocket(%v -> %v) = %d, %v, want %d", source, c.remote, inode, err, socketInodeOf(t, c.conn))
			}
		}
	})

	t.Run("udp", func(t *testing.T) {
		socket, err := stdnet.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer socket.Close()
		local := addrPortOf(socket.LocalAddr())
		if _, err := f.diagList(unix.IPPROTO_UDP, diagAllStates, local); err == errDiagUnsupported {
			t.Skip("no UDP sock_diag here")
		}
		remote := netip.MustParseAddrPort("198.51.100.1:53")
		if inode, _, err := f.diagExact(unix.IPPROTO_UDP, local, remote); err != nil || inode != socketInodeOf(t, socket) {
			t.Errorf("diagExact(%v -> %v) = %d, %v, want %d", local, remote, inode, err, socketInodeOf(t, socket))
		}
	})
}

// TestDiagFailed checks which errors of sock_diag stop its use until restart, and that the finder
// closes the netlink socket after an error.
func TestDiagFailed(t *testing.T) {
	for _, c := range []struct {
		name  string
		err   error
		off   [2]bool
		retry bool
	}{
		{"protocol not supported", errDiagUnsupported, [2]bool{true, false}, false},
		{"no permission", unix.EACCES, [2]bool{true, true}, false},
		{"no netlink protocol", unix.EPROTONOSUPPORT, [2]bool{true, true}, false},
		{"timeout", unix.EAGAIN, [2]bool{}, true},
		{"descriptor limit", unix.EMFILE, [2]bool{}, true},
	} {
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		f := &linuxFinder{diag: fd}
		f.diagFailed(diagTCP, c.err)
		if f.diagOff != c.off || time.Now().Before(f.diagRetry) != c.retry {
			t.Errorf("%s: off %v, retry %v, want off %v, retry %v", c.name, f.diagOff, time.Now().Before(f.diagRetry), c.off, c.retry)
		}
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); f.diag != -1 || err != unix.EBADF {
			t.Errorf("%s: the netlink socket stays open", c.name)
			unix.Close(fd)
		}
	}
}

// TestFindProcessNoOwnerCache checks that the finder remembers a socket without a process for
// noOwnerTime: the second search lists no descriptors.
func TestFindProcessNoOwnerCache(t *testing.T) {
	const inode = math.MaxUint32 - 1
	scans := 0
	testHookScan = func(int) { scans++ }
	defer func() { testHookScan = nil }()
	f := linuxProcessFinder
	f.mu.Lock()
	defer f.mu.Unlock()
	defer delete(f.noOwner, inode)
	for _, c := range []struct {
		name  string
		scans bool
	}{
		{"first search", true},
		{"second search", false},
		{"search after noOwnerTime", true},
	} {
		if c.name == "search after noOwnerTime" {
			f.noOwner[inode] = time.Now().Add(-time.Second)
		}
		scans = 0
		if pid, err := f.owner(inode, 0); pid != 0 || err != nil {
			t.Fatalf("%s: PID %d, %v, want no process", c.name, pid, err)
		}
		if (scans > 0) != c.scans {
			t.Errorf("%s: %d lists of descriptors", c.name, scans)
		}
	}
}

// TestDropEnded checks that the finder forgets an ended process, and the entries of an ended process
// whose PID a new process has: the mark of a process that was not readable and the open directory of
// a recent process.
func TestDropEnded(t *testing.T) {
	pid := os.Getpid()
	f := &linuxFinder{stats: make(map[int]procStat)}
	stat := f.stat(pid)
	for _, c := range []struct {
		name string
		pid  int
		proc func() *procFDs
		kept bool
	}{
		{"ended process", 1 << 30, func() *procFDs { return &procFDs{dir: -1} }, false},
		{"process that was not readable", pid, func() *procFDs {
			return &procFDs{dir: -1, uid: stat.uid, unreadable: true, procInode: stat.inode}
		}, true},
		{"new process after one that was not readable", pid, func() *procFDs {
			return &procFDs{dir: -1, uid: stat.uid, unreadable: true, procInode: stat.inode + 1}
		}, false},
		{"recent process", pid, func() *procFDs {
			dir, inode := openFDDir(pid)
			return &procFDs{dir: dir, dirInode: inode}
		}, true},
		{"new process after a recent one", pid, func() *procFDs {
			dir, inode := openFDDir(pid)
			return &procFDs{dir: dir, dirInode: inode + 1}
		}, false},
	} {
		proc := c.proc()
		f.procs = map[int]*procFDs{c.pid: proc}
		f.dropEnded([]int{pid})
		if _, kept := f.procs[c.pid]; kept != c.kept {
			t.Errorf("%s: kept %v, want %v", c.name, kept, c.kept)
		}
		if c.kept && proc.dir >= 0 {
			unix.Close(proc.dir)
		}
	}
}

// TestFindProcessRetryUnreadable checks the last step of a search: a process that was not readable
// at an earlier lookup gets one more read.
func TestFindProcessRetryUnreadable(t *testing.T) {
	listener := listenTCP(t, "tcp4", "127.0.0.1:0")
	conn := dialTCP(t, "tcp4", listener.Addr().String())
	pid := os.Getpid()
	f := &linuxFinder{
		diag:    -1,
		owners:  make(map[uint32]fdOwner),
		noOwner: make(map[uint32]time.Time),
		procs:   make(map[int]*procFDs),
		stats:   make(map[int]procStat),
		self:    pid,
	}
	defer func() {
		for _, proc := range f.procs {
			if proc.dir >= 0 {
				unix.Close(proc.dir)
			}
		}
	}()
	stat := f.stat(pid)
	f.procs[pid] = &procFDs{dir: -1, uid: stat.uid, unreadable: true, procInode: stat.inode}
	if got, err := f.owner(socketInodeOf(t, conn), stat.uid); err != nil || got != pid {
		t.Fatalf("owner = %d, %v, want %d", got, err, pid)
	}
	if proc := f.procs[pid]; proc == nil || proc.unreadable {
		t.Error("the process stays marked as not readable")
	}
}

// TestFindProcessProbe checks that the finder finds a new socket of a known process without a list
// of its descriptors: the socket gets the number of the closed socket. The helpers are more than
// the recent processes.
func TestFindProcessProbe(t *testing.T) {
	listener := listenTCP(t, "tcp4", "127.0.0.1:0")
	var helpers []*processHelper
	pids := make(map[int]bool)
	for range procRecentLimit + 4 {
		helper := startProcessHelper(t, listener, 500, 1)
		helpers = append(helpers, helper)
		pids[helper.cmd.Process.Pid] = true
	}
	scans := 0
	testHookScan = func(pid int) {
		if pids[pid] {
			scans++
		}
	}
	defer func() { testHookScan = nil }()
	for round := range 3 {
		for _, helper := range helpers {
			helper.connect(t, false)
			before := scans
			local := &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: helper.port}
			pid, _, _, err := lookupProcess(t, "tcp", local, listener.Addr())
			if err != nil || pid != helper.cmd.Process.Pid {
				t.Fatalf("FindProcess of the helper = %d, %v, want %d", pid, err, helper.cmd.Process.Pid)
			}
			// In the first round, the finder lists the helpers that it does not know yet.
			if round > 0 && scans != before {
				t.Errorf("round %d: the search listed the descriptors of %d helpers, want 0", round, scans-before)
			}
		}
	}
}

func TestListNumbers(t *testing.T) {
	// More descriptors than one read of the directory gives.
	var files []*os.File
	defer func() {
		for _, file := range files {
			file.Close()
		}
	}()
	for range 3000 {
		file, err := os.Open(os.DevNull)
		if errors.Is(err, unix.EMFILE) {
			t.Skip("the descriptor limit is too low: ", err)
		}
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	dir, err := os.Open("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		t.Fatal(err)
	}
	// The read above is at the end of the directory, so listNumbers gets its own descriptor.
	listed, err := unix.Open("/proc/self/fd", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(listed)
	numbers, err := (&linuxFinder{}).listNumbers(listed)
	if err != nil {
		t.Fatal(err)
	}
	// The list has the descriptor of the second directory, and Readdirnames does not.
	numbers = slices.DeleteFunc(numbers, func(fd int32) bool { return int(fd) == listed })
	if len(numbers) != len(names) {
		t.Errorf("listNumbers gave %d numbers, Readdirnames %d names", len(numbers), len(names))
	}
	for _, file := range files {
		if !slices.Contains(numbers, int32(file.Fd())) {
			t.Fatalf("listNumbers has no descriptor %d", file.Fd())
		}
	}
}

func TestListProcesses(t *testing.T) {
	pids, err := (&linuxFinder{}).listProcesses()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.IsSorted(pids) {
		t.Error("the process IDs are not in increasing order")
	}
	if _, found := slices.BinarySearch(pids, os.Getpid()); !found {
		t.Errorf("the list has no process %d", os.Getpid())
	}
}

func TestParseNumberName(t *testing.T) {
	for name, want := range map[string]int32{"0\x00": 0, "17\x00\x00": 17, "2147483647\x00": 2147483647} {
		if got, ok := parseNumberName([]byte(name)); !ok || got != want {
			t.Errorf("parseNumberName(%q) = %d, %v, want %d", name, got, ok, want)
		}
	}
	for _, name := range []string{".\x00", "..\x00", "\x00", "self\x00", "2147483648\x00", "1a\x00"} {
		if got, ok := parseNumberName([]byte(name)); ok {
			t.Errorf("parseNumberName(%q) = %d, want no number", name, got)
		}
	}
}

func TestSocketInode(t *testing.T) {
	for link, want := range map[string]uint32{
		"socket:[12345]":      12345,
		"socket:[4294967295]": 4294967295,
		"socket:[4294967296]": 0,
		"socket:[]":           0,
		"socket:[12a]":        0,
		"pipe:[12345]":        0,
		"/dev/null":           0,
	} {
		if got := socketInode([]byte(link)); got != want {
			t.Errorf("socketInode(%q) = %d, want %d", link, got, want)
		}
	}
}

func TestLowestFreeFDs(t *testing.T) {
	if got := lowestFreeFDs([]int32{0, 1, 2, 5, 7}, 4); !slices.Equal(got, []int32{3, 4, 6, 8}) {
		t.Errorf("lowestFreeFDs = %v", got)
	}
	if got := lowestFreeFDs(nil, 2); !slices.Equal(got, []int32{0, 1}) {
		t.Errorf("lowestFreeFDs(nil) = %v", got)
	}
}

func TestMergeFDs(t *testing.T) {
	if got := mergeFDs([]int32{1, 5, 9}, []int32{12, 5, 2}); !slices.Equal(got, []int32{1, 2, 5, 9, 12}) {
		t.Errorf("mergeFDs = %v", got)
	}
	odd := make([]int32, procSocketLimit)
	for i := range odd {
		odd[i] = int32(2*i + 1)
	}
	got := mergeFDs(odd, []int32{0})
	if len(got) != procSocketLimit || got[0] != 0 || got[len(got)-1] != odd[len(odd)-2] {
		t.Errorf("mergeFDs over the limit gave %d numbers from %d to %d", len(got), got[0], got[len(got)-1])
	}
}

func TestFDSet(t *testing.T) {
	set := newFDSet([]int32{0, 63, 64, 1000})
	for _, fd := range []int32{0, 63, 64, 1000} {
		if !set.has(fd) {
			t.Errorf("the set has no %d", fd)
		}
	}
	for _, fd := range []int32{-1, 1, 65, 999, fdSetLimit} {
		if set.has(fd) {
			t.Errorf("the set has %d", fd)
		}
	}
}

// netlinkMessage returns a netlink message with the type, the sequence number and the payload.
func netlinkMessage(kind uint16, sequence uint32, payload []byte) []byte {
	message := make([]byte, nlmsgHeaderSize+len(payload))
	binary.NativeEndian.PutUint32(message[0:], uint32(len(message)))
	binary.NativeEndian.PutUint16(message[4:], kind)
	binary.NativeEndian.PutUint32(message[8:], sequence)
	copy(message[nlmsgHeaderSize:], payload)
	return message
}

// netlinkErrno returns the payload of NLMSG_ERROR or NLMSG_DONE with the errno.
func netlinkErrno(errno unix.Errno) []byte {
	payload := make([]byte, 4)
	binary.NativeEndian.PutUint32(payload, uint32(-int32(errno)))
	return payload
}

func TestDiagAnswers(t *testing.T) {
	f := &linuxFinder{sequence: 7}
	socket := make([]byte, diagMessageSize)

	for _, c := range []struct {
		name   string
		answer []byte
		want   error
	}{
		{"socket", netlinkMessage(unix.SOCK_DIAG_BY_FAMILY, 7, socket), nil},
		{"no socket", netlinkMessage(unix.NLMSG_ERROR, 7, netlinkErrno(unix.ENOENT)), unix.ENOENT},
		{"acknowledgment", netlinkMessage(unix.NLMSG_ERROR, 7, netlinkErrno(0)), errDiagAnswer},
		{"earlier request", netlinkMessage(unix.SOCK_DIAG_BY_FAMILY, 6, socket), errStaleAnswer},
		{"short socket", netlinkMessage(unix.SOCK_DIAG_BY_FAMILY, 7, socket[:diagMessageSize-1]), errDiagAnswer},
		{"short header", netlinkMessage(unix.SOCK_DIAG_BY_FAMILY, 7, nil)[:nlmsgHeaderSize-1], errDiagAnswer},
		{"short error", netlinkMessage(unix.NLMSG_ERROR, 7, []byte{1}), errDiagAnswer},
	} {
		message, err := f.parse(c.answer)
		if err != c.want || err == nil && len(message) != diagMessageSize {
			t.Errorf("parse(%s) = %d bytes, %v, want %v", c.name, len(message), err, c.want)
		}
	}

	visits := 0
	visit := func([]byte) { visits++ }
	list := slices.Concat(
		netlinkMessage(unix.SOCK_DIAG_BY_FAMILY, 7, socket),
		netlinkMessage(unix.SOCK_DIAG_BY_FAMILY, 6, socket),
		netlinkMessage(unix.SOCK_DIAG_BY_FAMILY, 7, socket),
	)
	for _, c := range []struct {
		name     string
		datagram []byte
		done     bool
		want     error
		visits   int
	}{
		{"two sockets", list, false, nil, 2},
		{"end", slices.Concat(list, netlinkMessage(unix.NLMSG_DONE, 7, netlinkErrno(0))), true, nil, 2},
		{"end without errno", netlinkMessage(unix.NLMSG_DONE, 7, nil), true, nil, 0},
		{"failed dump", netlinkMessage(unix.NLMSG_DONE, 7, netlinkErrno(unix.ENOENT)), true, unix.ENOENT, 0},
		{"error", netlinkMessage(unix.NLMSG_ERROR, 7, netlinkErrno(unix.EACCES)), false, unix.EACCES, 0},
		{"cut datagram", list[:len(list)-1], false, errDiagAnswer, 1},
		{"short socket", netlinkMessage(unix.SOCK_DIAG_BY_FAMILY, 7, socket[:8]), false, errDiagAnswer, 0},
		{"other type", netlinkMessage(unix.RTM_NEWLINK, 7, nil), false, errDiagAnswer, 0},
	} {
		visits = 0
		done, err := f.parseList(c.datagram, visit)
		if done != c.done || err != c.want || visits != c.visits {
			t.Errorf("parseList(%s) = %v, %v, %d sockets, want %v, %v, %d", c.name, done, err, visits, c.done, c.want, c.visits)
		}
	}
}

func TestBetterDiagEntry(t *testing.T) {
	entry := func(family byte, source, remote string, inode uint32) []byte {
		message := make([]byte, diagMessageSize)
		message[0] = family
		sourceAddress := netip.MustParseAddrPort(source)
		binary.BigEndian.PutUint16(message[diagSourcePort:], sourceAddress.Port())
		putDiagAddress(message[diagSource:diagSource+16], family, sourceAddress.Addr())
		if remote != "" {
			remoteAddress := netip.MustParseAddrPort(remote)
			binary.BigEndian.PutUint16(message[diagRemotePort:], remoteAddress.Port())
			putDiagAddress(message[diagRemote:diagRemote+16], family, remoteAddress.Addr())
		}
		binary.NativeEndian.PutUint32(message[diagUID:], 1000)
		binary.NativeEndian.PutUint32(message[diagInode:], inode)
		return message
	}
	local := netip.MustParseAddrPort("127.0.0.1:40000")
	timeWait := entry(unix.AF_INET, "127.0.0.1:40000", "127.0.0.1:80", 0)
	other := entry(unix.AF_INET, "127.0.0.2:40000", "127.0.0.1:80", 11)
	unbound := entry(unix.AF_INET, "0.0.0.0:40000", "", 12)
	unbound6 := entry(unix.AF_INET6, "[::]:40000", "", 13)
	exact := entry(unix.AF_INET6, "[::ffff:127.0.0.1]:40000", "[::ffff:127.0.0.1]:1080", 14)
	otherPort := entry(unix.AF_INET, "127.0.0.1:40001", "127.0.0.1:80", 15)

	for _, c := range []struct {
		name     string
		messages [][]byte
		inode    uint32
		remote   string
	}{
		{"mapped address", [][]byte{timeWait, other, unbound, exact, unbound6}, 14, "127.0.0.1:1080"},
		{"first socket without an address", [][]byte{other, unbound6, unbound}, 13, ""},
		{"other address", [][]byte{other, timeWait}, 0, ""},
		{"other port", [][]byte{otherPort, unbound}, 12, ""},
	} {
		var best diagListEntry
		for _, message := range c.messages {
			best = betterDiagEntry(best, message, local)
		}
		var remote netip.AddrPort
		if c.remote != "" {
			remote = netip.MustParseAddrPort(c.remote)
		}
		if best.inode != c.inode || best.remote != remote || c.inode != 0 && best.uid != 1000 {
			t.Errorf("%s: inode %d, remote %v, uid %d, want inode %d, remote %v", c.name, best.inode, best.remote, best.uid, c.inode, remote)
		}
	}
}
