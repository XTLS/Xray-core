//go:build (linux && !android) || windows

package net

import (
	"bufio"
	"fmt"
	"io"
	"math/rand/v2"
	stdnet "net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The test binary is a helper process when processHelperAddress is set: see runProcessHelper.
const (
	processHelperAddress = "XRAY_FIND_PROCESS_HELPER"
	processHelperFiles   = "XRAY_FIND_PROCESS_HELPER_FILES"
	processHelperConns   = "XRAY_FIND_PROCESS_HELPER_CONNS"
)

func TestMain(m *testing.M) {
	if address := os.Getenv(processHelperAddress); address != "" {
		runProcessHelper(address)
	}
	os.Exit(m.Run())
}

// runProcessHelper opens processHelperFiles files and makes processHelperConns connections to the
// address, a file and a connection in turn. Then it prints "port <new> <closed>": the local port of
// its newest connection and of the connection that it closed, or 0. Each input line "connect"
// closes a random connection with a reset and makes a new one. The line "connect-file" also closes
// a random file and opens a new one before the new connection.
func runProcessHelper(address string) {
	files, _ := strconv.Atoi(os.Getenv(processHelperFiles))
	count, _ := strconv.Atoi(os.Getenv(processHelperConns))
	count = max(count, 1)
	check := func(err error) {
		if err != nil {
			fmt.Println("error", err)
			os.Exit(1)
		}
	}
	open := func() *os.File {
		file, err := os.Open(os.DevNull)
		check(err)
		return file
	}
	dial := func() *stdnet.TCPConn {
		conn, err := stdnet.Dial("tcp", address)
		check(err)
		return conn.(*stdnet.TCPConn)
	}
	port := func(conn *stdnet.TCPConn) int {
		return conn.LocalAddr().(*stdnet.TCPAddr).Port
	}
	opened := make([]*os.File, 0, files)
	conns := make([]*stdnet.TCPConn, 0, count)
	for i := range max(files, count) {
		if i < files {
			opened = append(opened, open())
		}
		if i < count {
			conns = append(conns, dial())
		}
	}
	fmt.Println("port", port(conns[count-1]), 0)
	input := bufio.NewScanner(os.Stdin)
	for input.Scan() {
		command := input.Text()
		if command != "connect" && command != "connect-file" {
			continue
		}
		i := rand.IntN(count)
		closed := port(conns[i])
		conns[i].SetLinger(0)
		conns[i].Close()
		if command == "connect-file" && len(opened) > 0 {
			j := rand.IntN(len(opened))
			opened[j].Close()
			opened[j] = open()
		}
		conns[i] = dial()
		fmt.Println("port", port(conns[i]), closed)
	}
	runtime.KeepAlive(opened)
	os.Exit(0)
}

// processHelper is the test binary as a helper process.
type processHelper struct {
	cmd   *exec.Cmd
	input io.WriteCloser
	lines chan string
	// port is the local port of the newest connection, closed the local port of the connection
	// that the last "connect" closed.
	port, closed int
}

func startProcessHelper(t testing.TB, listener stdnet.Listener, files, conns int) *processHelper {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), processHelperAddress+"="+listener.Addr().String(),
		processHelperFiles+"="+strconv.Itoa(files), processHelperConns+"="+strconv.Itoa(conns))
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		input.Close()
		cmd.Process.Kill()
		cmd.Wait()
	})
	helper := &processHelper{cmd: cmd, input: input, lines: make(chan string, 1)}
	go func() {
		lines := bufio.NewScanner(output)
		for lines.Scan() {
			helper.lines <- lines.Text()
		}
		close(helper.lines)
	}()
	helper.readPort(t)
	return helper
}

// connect makes the helper replace a connection, and with file also a file.
func (h *processHelper) connect(t testing.TB, file bool) {
	t.Helper()
	command := "connect\n"
	if file {
		command = "connect-file\n"
	}
	if _, err := io.WriteString(h.input, command); err != nil {
		t.Fatal(err)
	}
	h.readPort(t)
}

func (h *processHelper) readPort(t testing.TB) {
	t.Helper()
	select {
	case line, ok := <-h.lines:
		if !ok {
			t.Fatal("the helper process ended")
		}
		if _, err := fmt.Sscanf(line, "port %d %d", &h.port, &h.closed); err != nil {
			t.Fatalf("helper output %q", line)
		}
	case <-time.After(30 * time.Second):
		h.cmd.Process.Kill()
		t.Fatal("the helper process gave no port in 30 s")
	}
}

// lookupProcess calls FindProcess with the addresses of a socket. remote can be nil.
func lookupProcess(t testing.TB, network string, local, remote stdnet.Addr) (int, string, string, error) {
	t.Helper()
	l := netip.MustParseAddrPort(local.String())
	var dstIP string
	var dstPort uint16
	if remote != nil {
		r := netip.MustParseAddrPort(remote.String())
		dstIP, dstPort = r.Addr().Unmap().String(), r.Port()
	}
	return FindProcess(network, l.Addr().Unmap().String(), l.Port(), dstIP, dstPort)
}

// wantOwnProcess checks that FindProcess finds the test process for the socket.
func wantOwnProcess(t *testing.T, network string, local, remote stdnet.Addr) {
	t.Helper()
	pid, name, path, err := lookupProcess(t, network, local, remote)
	if err != nil {
		t.Fatalf("FindProcess(%s %s -> %v) error: %v", network, local, remote, err)
	}
	if pid != os.Getpid() {
		t.Fatalf("FindProcess(%s %s -> %v) PID = %d, want %d", network, local, remote, pid, os.Getpid())
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Two paths of the same file can differ in the case of the letters, or in the short names of
	// Windows.
	want, err := os.Stat(executable)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.Stat(path); err != nil || !os.SameFile(got, want) {
		t.Errorf("path = %q, want %q", path, executable)
	}
	wantName := filepath.Base(executable)
	if runtime.GOOS == "windows" {
		wantName = strings.TrimSuffix(wantName, ".exe")
	}
	if !strings.EqualFold(name, wantName) {
		t.Errorf("name = %q, want %q", name, wantName)
	}
}

// listenTCP accepts each connection until the end of the test. It skips the test if the system
// has no IPv6 loopback address.
func listenTCP(t testing.TB, network, address string) stdnet.Listener {
	t.Helper()
	if network == "tcp6" && !hasIPv6Loopback() {
		t.Skip("no IPv6 loopback address here")
	}
	listener, err := stdnet.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu    sync.Mutex
		conns []stdnet.Conn
	)
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			conn.Close()
		}
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()
	return listener
}

// hasIPv6Loopback reports whether an interface has the address ::1.
func hasIPv6Loopback() bool {
	addresses, err := stdnet.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, address := range addresses {
		if ipNet, ok := address.(*stdnet.IPNet); ok && ipNet.IP.Equal(stdnet.IPv6loopback) {
			return true
		}
	}
	return false
}

func dialTCP(t testing.TB, network, address string) stdnet.Conn {
	t.Helper()
	conn, err := stdnet.Dial(network, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// testFindProcessTCP checks a connection with its remote address, as in TUN mode, and with another
// target or none, as through a local proxy. New connections get the descriptors of closed ones.
func testFindProcessTCP(t *testing.T, network, address string) {
	listener := listenTCP(t, network, address)
	conn := dialTCP(t, network, listener.Addr().String())
	target := &stdnet.TCPAddr{IP: stdnet.ParseIP("203.0.113.1"), Port: 443}
	wantOwnProcess(t, "tcp", conn.LocalAddr(), conn.RemoteAddr())
	wantOwnProcess(t, "tcp", conn.LocalAddr(), target)
	wantOwnProcess(t, "tcp", conn.LocalAddr(), nil)

	for i := range 64 {
		conn, err := stdnet.Dial(network, listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 {
			wantOwnProcess(t, "tcp", conn.LocalAddr(), conn.RemoteAddr())
		} else {
			wantOwnProcess(t, "tcp", conn.LocalAddr(), target)
		}
		if i%3 == 0 {
			conn.Close()
		} else {
			t.Cleanup(func() { conn.Close() })
		}
	}
}

func TestFindProcessTCP(t *testing.T) {
	testFindProcessTCP(t, "tcp4", "127.0.0.1:0")
}

func TestFindProcessTCP6(t *testing.T) {
	testFindProcessTCP(t, "tcp6", "[::1]:0")
}

func TestFindProcessUDP(t *testing.T) {
	peer, err := stdnet.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	target := &stdnet.UDPAddr{IP: stdnet.ParseIP("198.51.100.1"), Port: 53}

	bound, err := stdnet.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Close()
	wantOwnProcess(t, "udp", bound.LocalAddr(), target)
	wantOwnProcess(t, "udp", bound.LocalAddr(), nil)

	// A socket without an address: a datagram has the address of the interface.
	wildcard, err := stdnet.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer wildcard.Close()
	wildcard.WriteTo([]byte{0}, peer.LocalAddr())
	port := wildcard.LocalAddr().(*stdnet.UDPAddr).Port
	wantOwnProcess(t, "udp", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: port}, target)

	// A socket with a connection.
	connected, err := stdnet.Dial("udp4", peer.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connected.Close()
	wantOwnProcess(t, "udp", connected.LocalAddr(), connected.RemoteAddr())
	wantOwnProcess(t, "udp", connected.LocalAddr(), target)

	for range 32 {
		socket, err := stdnet.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		wantOwnProcess(t, "udp", socket.LocalAddr(), target)
		socket.Close()
	}
}

func TestFindProcessUDP6(t *testing.T) {
	if !hasIPv6Loopback() {
		t.Skip("no IPv6 loopback address here")
	}
	socket, err := stdnet.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	wantOwnProcess(t, "udp", socket.LocalAddr(), &stdnet.UDPAddr{IP: stdnet.ParseIP("2001:db8::1"), Port: 53})
}

func TestFindProcessNotFound(t *testing.T) {
	if pid, _, _, err := lookupProcess(t, "tcp", &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 1}, nil); err == nil {
		t.Errorf("FindProcess of a TCP port without a socket: PID %d, want an error", pid)
	}
	if pid, _, _, err := lookupProcess(t, "udp", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 1}, nil); err == nil {
		t.Errorf("FindProcess of a UDP port without a socket: PID %d, want an error", pid)
	}
}

func TestFindProcessOtherProcess(t *testing.T) {
	listener := listenTCP(t, "tcp4", "127.0.0.1:0")
	var helpers []*processHelper
	for range 3 {
		helpers = append(helpers, startProcessHelper(t, listener, 0, 1))
	}
	// Each round gives each helper a new connection: a known process gets a new socket.
	for round := range 3 {
		for _, helper := range helpers {
			if round > 0 {
				helper.connect(t, false)
			}
			local := &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: helper.port}
			for _, remote := range []stdnet.Addr{listener.Addr(), nil} {
				pid, _, _, err := lookupProcess(t, "tcp", local, remote)
				if err != nil {
					t.Fatalf("FindProcess of the helper error: %v", err)
				}
				if pid != helper.cmd.Process.Pid {
					t.Fatalf("FindProcess of the helper PID = %d, want %d", pid, helper.cmd.Process.Pid)
				}
			}
			// The connections of the test process stay correct after a search in another process.
			conn := dialTCP(t, "tcp4", listener.Addr().String())
			wantOwnProcess(t, "tcp", conn.LocalAddr(), conn.RemoteAddr())
		}
	}
}

// BenchmarkFindProcess measures FindProcess with many open sockets of the benchmark process. Each
// TCP connection has two sockets. A new connection ends with a reset, so the number of sockets
// stays the same. The cases:
//
//   - existing: the same connection each time, as a second process rule of a connection.
//   - new: a new connection each time, with its remote address, as in TUN mode.
//   - new-proxy: a new connection each time with a different target, as a program that connects
//     to a local proxy.
//   - new-udp: a new UDP socket each time.
//
// The benchmarks time only the FindProcess calls: ns/op is the mean of the calls, p50-ns their
// median and p99-ns their 99th percentile.
func BenchmarkFindProcess(b *testing.B) {
	for _, sockets := range []int{200, 2000} {
		b.Run(fmt.Sprintf("sockets=%d", sockets), func(b *testing.B) {
			listener := newBenchListener(b)
			var last stdnet.Conn
			for range sockets / 2 {
				client, server := listener.connect(b)
				b.Cleanup(func() { resetConns(server, client) })
				last = client
			}
			target := &stdnet.TCPAddr{IP: stdnet.ParseIP("198.51.100.1"), Port: 443}

			b.Run("existing", func(b *testing.B) {
				measureFindProcess(b, "tcp", func() (stdnet.Addr, stdnet.Addr, func()) {
					return last.LocalAddr(), last.RemoteAddr(), func() {}
				})
			})
			b.Run("new", func(b *testing.B) {
				measureFindProcess(b, "tcp", func() (stdnet.Addr, stdnet.Addr, func()) {
					client, server := listener.connect(b)
					return client.LocalAddr(), client.RemoteAddr(), func() { resetConns(client, server) }
				})
			})
			b.Run("new-proxy", func(b *testing.B) {
				measureFindProcess(b, "tcp", func() (stdnet.Addr, stdnet.Addr, func()) {
					client, server := listener.connect(b)
					return client.LocalAddr(), target, func() { resetConns(client, server) }
				})
			})
			b.Run("new-udp", func(b *testing.B) {
				udpTarget := &stdnet.UDPAddr{IP: stdnet.ParseIP("198.51.100.1"), Port: 53}
				measureFindProcess(b, "udp", func() (stdnet.Addr, stdnet.Addr, func()) {
					socket, err := stdnet.ListenPacket("udp4", "127.0.0.1:0")
					if err != nil {
						b.Fatal(err)
					}
					return socket.LocalAddr(), udpTarget, func() { socket.Close() }
				})
			})
		})
	}
}

// BenchmarkFindProcessManySockets measures the new connections of another process with 100
// connections and 100 open files, as a browser. For each call, the process closes a random
// connection and makes a new one. With replace=socket+file, it also closes a random file and opens
// a new one before the new connection, so the new socket often gets the number of a closed file.
func BenchmarkFindProcessManySockets(b *testing.B) {
	const conns, files = 100, 100
	for _, file := range []bool{false, true} {
		name := "replace=socket"
		if file {
			name = "replace=socket+file"
		}
		b.Run(name, func(b *testing.B) {
			listener := newBenchListener(b)
			helper := startProcessHelper(b, listener.listener, files, conns)
			servers := make(map[int]stdnet.Conn, conns)
			for range conns {
				server := listener.accept(b)
				servers[server.RemoteAddr().(*stdnet.TCPAddr).Port] = server
			}
			b.Cleanup(func() {
				for _, server := range servers {
					resetConns(server)
				}
			})
			measureFindProcess(b, "tcp", func() (stdnet.Addr, stdnet.Addr, func()) {
				helper.connect(b, file)
				if old, ok := servers[helper.closed]; ok {
					resetConns(old)
					delete(servers, helper.closed)
				}
				servers[helper.port] = listener.accept(b)
				local := &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: helper.port}
				return local, listener.listener.Addr(), func() {}
			})
		})
	}
}

// BenchmarkFindProcessManyProcesses measures the new connections of other processes on a computer
// with many descriptors: 40 helper processes with 2500 open files each. Each call is for the next
// helper in turn, so the 39 calls before it were for other processes. Only the lookup of Linux
// reads the descriptors of the processes.
func BenchmarkFindProcessManyProcesses(b *testing.B) {
	if runtime.GOOS != "linux" {
		b.Skip("only the lookup of Linux reads the descriptors of the processes")
	}
	const helpers, files = 40, 2500
	listener := newBenchListener(b)
	processes := make([]*processHelper, helpers)
	for i := range processes {
		processes[i] = startProcessHelper(b, listener.listener, files, 1)
		server := listener.accept(b)
		b.Cleanup(func() { resetConns(server) })
	}
	next := 0
	measureFindProcess(b, "tcp", func() (stdnet.Addr, stdnet.Addr, func()) {
		helper := processes[next%helpers]
		next++
		helper.connect(b, false)
		server := listener.accept(b)
		local := &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: helper.port}
		return local, listener.listener.Addr(), func() { resetConns(server) }
	})
}

// benchListener gives each connection with both of its sockets.
type benchListener struct {
	listener stdnet.Listener
	accepted chan stdnet.Conn
}

func newBenchListener(b *testing.B) *benchListener {
	listener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	l := &benchListener{listener: listener, accepted: make(chan stdnet.Conn, 1)}
	b.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				close(l.accepted)
				return
			}
			l.accepted <- conn
		}
	}()
	return l
}

func (l *benchListener) accept(b *testing.B) stdnet.Conn {
	select {
	case server, ok := <-l.accepted:
		if !ok {
			b.Fatal("the listener closed")
		}
		return server
	case <-time.After(30 * time.Second):
		b.Fatal("no connection in 30 s")
		return nil
	}
}

func (l *benchListener) connect(b *testing.B) (client, server stdnet.Conn) {
	client, err := stdnet.Dial("tcp4", l.listener.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	return client, l.accept(b)
}

// resetConns closes the connections with a reset. A closed connection then leaves no socket in
// TIME_WAIT: the number of sockets stays the same, and a new connection cannot get the port of such
// a socket.
func resetConns(conns ...stdnet.Conn) {
	for _, conn := range conns {
		conn.(*stdnet.TCPConn).SetLinger(0)
		conn.Close()
	}
}

// measureFindProcess calls FindProcess for the sockets of next and times only the calls with
// b.Elapsed, which uses QueryPerformanceCounter on Windows. StopTimer and StartTimer would read the
// memory statistics around each call and stop the world.
func measureFindProcess(b *testing.B, network string, next func() (local, remote stdnet.Addr, done func())) {
	samples := make([]time.Duration, 0, b.N)
	var total time.Duration
	for range b.N {
		local, remote, done := next()
		l := netip.MustParseAddrPort(local.String())
		r := netip.MustParseAddrPort(remote.String())
		srcIP, dstIP := l.Addr().Unmap().String(), r.Addr().Unmap().String()
		before := b.Elapsed()
		_, _, _, err := FindProcess(network, srcIP, l.Port(), dstIP, r.Port())
		sample := b.Elapsed() - before
		samples = append(samples, sample)
		total += sample
		done()
		if err != nil {
			b.Fatal(err)
		}
	}
	slices.Sort(samples)
	b.ReportMetric(float64(total.Nanoseconds())/float64(b.N), "ns/op")
	b.ReportMetric(float64(samples[len(samples)/2].Nanoseconds()), "p50-ns")
	b.ReportMetric(float64(samples[len(samples)*99/100].Nanoseconds()), "p99-ns")
}
