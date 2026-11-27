//go:build windows

package net

import (
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
	"time"
)

// TestFindProcessTables checks the search without nsi.dll: the finder then reads the socket tables.
func TestFindProcessTables(t *testing.T) {
	once.Do(func() { initErr = initWin32API() })
	if initErr != nil {
		t.Fatal(initErr)
	}
	f := windowsProcessFinder
	f.mu.Lock()
	nsi := f.nsi
	f.nsi = false
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.nsi = nsi
		f.mu.Unlock()
	}()
	testFindProcessTCP(t, "tcp4", "127.0.0.1:0")
	testFindProcessTCP(t, "tcp6", "[::1]:0")
}

// TestFindProcessNSI checks that the TCP searches use nsi.dll and that a result of it matched the
// TCP table. The finder stops using nsi.dll after a status code that it does not expect: the test
// then skips, and it fails only after a mismatch with the table.
func TestFindProcessNSI(t *testing.T) {
	once.Do(func() { initErr = initWin32API() })
	if initErr != nil {
		t.Fatal(initErr)
	}
	checkNSI := func() [2]bool {
		f := windowsProcessFinder
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case f.nsiError == errNSIMismatch:
			t.Fatal(errNSIMismatch)
		case !f.nsi && f.nsiError == nil:
			t.Skip("no NsiGetAllParameters here")
		case !f.nsi:
			t.Skip("the finder stopped using NsiGetAllParameters: ", f.nsiError)
		}
		return f.nsiChecked
	}
	checkNSI()
	testFindProcessTCP(t, "tcp4", "127.0.0.1:0")
	testFindProcessTCP(t, "tcp6", "[::1]:0")
	if checked := checkNSI(); !checked[0] || !checked[1] {
		t.Errorf("results of NsiGetAllParameters that matched the TCP table: IPv4 %v, IPv6 %v, want both", checked[0], checked[1])
	}
}

// TestFindProcessStaleTable checks the rows of a cached TCP table. A row with another remote address
// can belong to a connection that has ended, and a row can name a process that has ended: then the
// finder reads the table again.
func TestFindProcessStaleTable(t *testing.T) {
	once.Do(func() { initErr = initWin32API() })
	if initErr != nil {
		t.Fatal(initErr)
	}
	listener := listenTCP(t, "tcp4", "127.0.0.1:0")
	conn := dialTCP(t, "tcp4", listener.Addr().String())
	local := netip.MustParseAddrPort(conn.LocalAddr().String())
	remote := netip.MustParseAddrPort(conn.RemoteAddr().String())
	// The process 4 is System, and no process has the ID 0xFFFFFFFC.
	for _, c := range []struct {
		name string
		row  testRow
	}{
		{"other remote address", testRow{tcpEstablished, local.String(), "127.0.0.1:1", 4}},
		{"ended process", testRow{tcpEstablished, local.String(), remote.String(), 0xFFFFFFFC}},
	} {
		f := &windowsFinder{paths: make(map[uint32]processPath), sweepAt: pathSweepMin}
		f.tables[socketTableTCP4] = socketTable{fetched: time.Now(), buf: makeSocketTable(&tcp4Row, c.row)}
		if pid, _, err := f.find(false, local, remote); err != nil || pid != uint32(os.Getpid()) {
			t.Errorf("%s: PID %d, %v, want %d", c.name, pid, err, os.Getpid())
		}
	}
}

// TestPathCacheSweep checks that a sweep closes the handle of an ended process and keeps the
// handle of a live process.
func TestPathCacheSweep(t *testing.T) {
	listener := listenTCP(t, "tcp4", "127.0.0.1:0")
	helper := startProcessHelper(t, listener, 0, 1)
	pid := uint32(helper.cmd.Process.Pid)
	f := &windowsFinder{paths: make(map[uint32]processPath), sweepAt: pathSweepMin}
	if _, err := f.path(pid); err != nil {
		t.Fatal(err)
	}
	f.sweep()
	if _, cached := f.paths[pid]; !cached {
		t.Fatal("the cache has no entry for the live process")
	}
	helper.cmd.Process.Kill()
	helper.cmd.Wait()
	f.sweep()
	if len(f.paths) != 0 {
		t.Errorf("the cache keeps %d entries after the end of the process", len(f.paths))
	}
}

// testRow is a row of a socket table.
type testRow struct {
	state         uint32
	local, remote string
	pid           uint32
}

// makeSocketTable returns a socket table with the rows in the layout.
func makeSocketTable(layout *socketRowLayout, rows ...testRow) []byte {
	table := make([]byte, 4+len(rows)*layout.size)
	binary.LittleEndian.PutUint32(table, uint32(len(rows)))
	for i, r := range rows {
		row := table[4+i*layout.size : 4+(i+1)*layout.size]
		// The state of a UDP row has the offset 0, and the address replaces it.
		binary.LittleEndian.PutUint32(row[layout.state:], r.state)
		local := netip.MustParseAddrPort(r.local)
		copy(row[layout.localAddr:], local.Addr().AsSlice())
		binary.BigEndian.PutUint16(row[layout.localPort:], local.Port())
		if r.remote != "" {
			remote := netip.MustParseAddrPort(r.remote)
			copy(row[layout.remoteAddr:], remote.Addr().AsSlice())
			binary.BigEndian.PutUint16(row[layout.remotePort:], remote.Port())
		}
		binary.LittleEndian.PutUint32(row[layout.pid:], r.pid)
	}
	return table
}

func TestSearchTCPTable(t *testing.T) {
	const synSent = 3
	tcp4 := makeSocketTable(&tcp4Row,
		testRow{tcpEstablished, "127.0.0.1:5000", "127.0.0.1:1080", 1},
		testRow{tcpEstablished, "127.0.0.1:5000", "127.0.0.1:8080", 2},
		testRow{synSent, "127.0.0.1:6000", "127.0.0.1:8080", 3},
		testRow{tcpEstablished, "0.0.0.0:6000", "127.0.0.1:8080", 4},
	)
	tcp6 := makeSocketTable(&tcp6Row, testRow{tcpEstablished, "[::1]:5000", "[::1]:443", 9})
	for _, c := range []struct {
		name          string
		table         []byte
		layout        *socketRowLayout
		local, remote string
		pid           uint32
		target        string
	}{
		{"remote address", tcp4, &tcp4Row, "127.0.0.1:5000", "127.0.0.1:8080", 2, "127.0.0.1:8080"},
		{"other remote address", tcp4, &tcp4Row, "127.0.0.1:5000", "203.0.113.1:443", 1, "127.0.0.1:1080"},
		{"no established connection", tcp4, &tcp4Row, "127.0.0.1:6000", "127.0.0.1:8080", 0, ""},
		{"incomplete row", tcp4[:4+2*tcp4Row.size+10], &tcp4Row, "127.0.0.1:5000", "127.0.0.1:8080", 2, "127.0.0.1:8080"},
		{"no rows", nil, &tcp4Row, "127.0.0.1:5000", "127.0.0.1:8080", 0, ""},
		{"IPv6", tcp6, &tcp6Row, "[::1]:5000", "[::1]:443", 9, "[::1]:443"},
	} {
		pid, target, found := searchTCPTable(c.table, c.layout, netip.MustParseAddrPort(c.local), netip.MustParseAddrPort(c.remote))
		var want netip.AddrPort
		if c.target != "" {
			want = netip.MustParseAddrPort(c.target)
		}
		if pid != c.pid || target != want || found != (c.pid != 0) {
			t.Errorf("%s: %d, %v, %v, want %d, %v", c.name, pid, target, found, c.pid, want)
		}
	}
}

func TestSearchUDPTable(t *testing.T) {
	udp4 := makeSocketTable(&udp4Row,
		testRow{local: "0.0.0.0:53", pid: 7},
		testRow{local: "127.0.0.1:53", pid: 8},
		testRow{local: "127.0.0.1:54", pid: 9},
	)
	udp6 := makeSocketTable(&udp6Row, testRow{local: "[::1]:53", pid: 5})
	for _, c := range []struct {
		name   string
		table  []byte
		layout *socketRowLayout
		local  string
		pid    uint32
	}{
		{"first socket", udp4, &udp4Row, "127.0.0.1:53", 7},
		{"address", udp4, &udp4Row, "127.0.0.1:54", 9},
		{"other address", udp4, &udp4Row, "127.0.0.2:54", 0},
		{"IPv6", udp6, &udp6Row, "[::1]:53", 5},
	} {
		pid, found := searchUDPTable(c.table, c.layout, netip.MustParseAddrPort(c.local))
		if pid != c.pid || found != (c.pid != 0) {
			t.Errorf("%s: %d, %v, want %d", c.name, pid, found, c.pid)
		}
	}
}
