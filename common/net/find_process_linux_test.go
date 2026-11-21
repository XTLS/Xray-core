//go:build linux && !android

package net

import (
	"errors"
	stdnet "net"
	"net/netip"
	"os"
	"syscall"
	"testing"
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
