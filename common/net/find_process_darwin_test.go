//go:build darwin

package net

import (
	stdnet "net"
	"net/netip"
	"os"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestFindProcessDarwinTCP(t *testing.T) {
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan stdnet.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
			return
		}
		close(accepted)
	}()

	conn, err := stdnet.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	serverConn := <-accepted
	if serverConn == nil {
		t.Fatal("server did not accept tcp connection")
	}
	defer serverConn.Close()

	local := conn.LocalAddr().(*stdnet.TCPAddr)
	remote := conn.RemoteAddr().(*stdnet.TCPAddr)

	pid, name, path, err := FindProcess("tcp", local.IP.String(), uint16(local.Port), remote.IP.String(), uint16(remote.Port))
	if err != nil {
		t.Fatal(err)
	}
	assertCurrentProcess(t, pid, name, path)
}

func TestFindProcessDarwinUDP(t *testing.T) {
	conn, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	local := conn.LocalAddr().(*stdnet.UDPAddr)

	pid, name, path, err := FindProcess("udp", local.IP.String(), uint16(local.Port), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	assertCurrentProcess(t, pid, name, path)
}

func TestFindProcessDarwinNonLocal(t *testing.T) {
	_, _, _, err := FindProcess("tcp", "203.0.113.1", 80, "", 0)
	if err != ErrNotLocal {
		t.Fatalf("expected ErrNotLocal, got %v", err)
	}
}

func TestFindProcessDarwinUnsupportedNetwork(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()

	_, _, _, _ = FindProcess("icmp", "127.0.0.1", 0, "", 0)
}

func assertCurrentProcess(t *testing.T, pid int, name string, path string) {
	t.Helper()

	if pid != os.Getpid() {
		t.Fatalf("expected pid %d, got %d (%s, %s)", os.Getpid(), pid, name, path)
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if path == "" || name == "" {
		t.Fatalf("expected process path and name, got name=%q path=%q", name, path)
	}
	if sameFile(executable, path) {
		return
	}
	t.Fatalf("expected executable %q, got %q", executable, path)
}

func sameFile(left string, right string) bool {
	leftInfo, leftErr := os.Stat(left)
	rightInfo, rightErr := os.Stat(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	return os.SameFile(leftInfo, rightInfo)
}

func TestFindProcessDarwinTCPWithoutDestination(t *testing.T) {
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan stdnet.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
			return
		}
		close(accepted)
	}()

	conn, err := stdnet.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	serverConn := <-accepted
	if serverConn == nil {
		t.Fatal("server did not accept tcp connection")
	}
	defer serverConn.Close()

	local := conn.LocalAddr().(*stdnet.TCPAddr)
	pid, name, path, err := FindProcess("tcp", local.IP.String(), uint16(local.Port), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	assertCurrentProcess(t, pid, name, path)
}

func TestFindProcessDarwinTCPWithDifferentDestination(t *testing.T) {
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan stdnet.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
			return
		}
		close(accepted)
	}()

	conn, err := stdnet.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	serverConn := <-accepted
	if serverConn == nil {
		t.Fatal("server did not accept tcp connection")
	}
	defer serverConn.Close()

	local := conn.LocalAddr().(*stdnet.TCPAddr)
	pid, name, path, err := FindProcess("tcp", local.IP.String(), uint16(local.Port), "203.0.113.10", 443)
	if err != nil {
		t.Fatal(err)
	}
	assertCurrentProcess(t, pid, name, path)
}

func TestDarwinSocketInfoMatchLevelFallbacks(t *testing.T) {
	src := netip.MustParseAddr("198.18.0.2")
	dst := netip.MustParseAddr("203.0.113.10")
	otherLocal := netip.MustParseAddr("192.168.1.10")
	otherRemote := netip.MustParseAddr("198.51.100.10")

	tests := []struct {
		name      string
		local     netip.Addr
		remote    netip.Addr
		hasDst    bool
		wantLevel darwinSocketMatchLevel
	}{
		{
			name:      "exact",
			local:     src,
			remote:    dst,
			hasDst:    true,
			wantLevel: darwinSocketExactMatch,
		},
		{
			name:      "local match with different remote",
			local:     src,
			remote:    otherRemote,
			hasDst:    true,
			wantLevel: darwinSocketLocalMatch,
		},
		{
			name:      "remote match with different local",
			local:     otherLocal,
			remote:    dst,
			hasDst:    true,
			wantLevel: darwinSocketRemoteMatch,
		},
		{
			name:      "port only with destination",
			local:     otherLocal,
			remote:    otherRemote,
			hasDst:    true,
			wantLevel: darwinSocketPortMatch,
		},
		{
			name:      "different local without destination",
			local:     otherLocal,
			remote:    otherRemote,
			hasDst:    false,
			wantLevel: darwinSocketNoMatch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info := newDarwinSocketInfo("tcp", test.local, 12345, test.remote, 443)
			level := darwinSocketInfoMatchLevel(info, "tcp", src, 12345, dst, 443, test.hasDst)
			if level != test.wantLevel {
				t.Fatalf("unexpected match level: got %d, want %d", level, test.wantLevel)
			}
		})
	}
}

func newDarwinSocketInfo(network string, local netip.Addr, localPort uint16, remote netip.Addr, remotePort uint16) []byte {
	info := make([]byte, darwinSocketFDInfoSize)
	switch network {
	case "tcp":
		writeDarwinNativeUint32(info, darwinSocketInfoProtoOff, uint32(unix.IPPROTO_TCP))
		writeDarwinNativeUint32(info, darwinSocketInfoKindOff, uint32(darwinSockInfoTCP))
	case "udp":
		writeDarwinNativeUint32(info, darwinSocketInfoProtoOff, uint32(unix.IPPROTO_UDP))
		writeDarwinNativeUint32(info, darwinSocketInfoKindOff, uint32(darwinSockInfoIN))
	}
	writeDarwinNativeUint32(info, darwinSocketInfoFamilyOff, uint32(unix.AF_INET))
	info[darwinInSockInfoVFlagOff] = darwinInSockInfoIPv4
	writeDarwinNativeUint32(info, darwinInSockInfoLPortOff, uint32(localPort))
	writeDarwinNativeUint32(info, darwinInSockInfoFPortOff, uint32(remotePort))
	copyDarwinIPv4(info[darwinInSockInfoLAddrOff:darwinInSockInfoLAddrOff+16], local)
	copyDarwinIPv4(info[darwinInSockInfoFAddrOff:darwinInSockInfoFAddrOff+16], remote)
	return info
}

func writeDarwinNativeUint32(b []byte, offset int, value uint32) {
	*(*uint32)(unsafe.Pointer(&b[offset])) = value
}

func copyDarwinIPv4(dst []byte, addr netip.Addr) {
	ip := addr.As4()
	copy(dst[12:16], ip[:])
}
