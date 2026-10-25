package internet_test

import (
	"context"
	gonet "net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
	. "github.com/xtls/xray-core/transport/internet"
)

func TestDialWithLocalAddr(t *testing.T) {
	server := &tcp.Server{}
	dest, err := server.Start()
	common.Must(err)
	defer server.Close()

	conn, err := DialSystem(context.Background(), net.TCPDestination(net.LocalHostIP, dest.Port), nil)
	common.Must(err)
	if r := cmp.Diff(conn.RemoteAddr().String(), "127.0.0.1:"+dest.Port.String()); r != "" {
		t.Error(r)
	}
	conn.Close()
}

func TestDialUDPToIPv6(t *testing.T) {
	peer, err := gonet.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback: ", err)
	}
	defer peer.Close()

	port := net.Port(peer.LocalAddr().(*gonet.UDPAddr).Port)
	conn, err := DialSystem(context.Background(), net.UDPDestination(net.LocalHostIPv6, port), nil)
	common.Must(err)
	defer conn.Close()

	// Without IPv4-mapped addresses (OpenBSD) a socket bound to 0.0.0.0
	// fails here with "non-IPv4 address"
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := peer.ReadFrom(buf); err != nil {
		t.Fatal(err)
	}
}
