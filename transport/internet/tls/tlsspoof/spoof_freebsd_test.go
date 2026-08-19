package tlsspoof

import (
	"net"
	"net/netip"
	"os/user"
	"testing"

	"golang.org/x/sys/unix"
)

func TestFreeBSDTCPSequence(t *testing.T) {
	u, err := user.Current()
	if err == nil && u.Uid != "0" {
		t.Skip("skipping test; must be root to use raw sockets / TCP_INFO on FreeBSD")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

	serverDone := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Write([]byte("hello"))
			conn.Close()
		}
		close(serverDone)
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer client.Close()

	tcpConn, ok := client.(*net.TCPConn)
	if !ok {
		t.Fatalf("expected *net.TCPConn, got %T", client)
	}

	sndNxt, rcvNxt, err := readFreeBSDTCPSequence(tcpConn)
	if err != nil {
		t.Fatalf("readFreeBSDTCPSequence failed: %v", err)
	}

	if sndNxt == 0 && rcvNxt == 0 {
		t.Errorf("expected non-zero sequence numbers, got sndNxt=%d rcvNxt=%d", sndNxt, rcvNxt)
	}
	t.Logf("FreeBSD TCP sequence retrieved: snd_nxt=%d, rcv_nxt=%d", sndNxt, rcvNxt)
	<-serverDone
}

func TestFreeBSDRawSocket(t *testing.T) {
	u, err := user.Current()
	if err == nil && u.Uid != "0" {
		t.Skip("skipping test; must be root to open raw sockets")
	}

	dst := netip.MustParseAddrPort("8.8.8.8:443")
	src := netip.MustParseAddrPort("127.0.0.1:12345")

	fd, sockaddr, err := openFreeBSDRawSocket(src, dst)
	if err != nil {
		t.Fatalf("openFreeBSDRawSocket failed: %v", err)
	}
	defer func() {
		if fd >= 0 {
			unix.Close(fd)
		}
	}()

	if fd < 0 {
		t.Errorf("expected valid fd, got %d", fd)
	}
	if sockaddr == nil {
		t.Error("expected valid sockaddr, got nil")
	}
}
