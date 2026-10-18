package http

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type testDialer struct{}

func (testDialer) Dial(ctx context.Context, dest net.Destination) (stat.Connection, error) {
	return net.Dial("tcp", dest.NetAddr())
}

func (testDialer) DestIpAddress() net.IP { return nil }

func (testDialer) SetOutboundGateway(ctx context.Context, ob *session.Outbound) {}

func TestHTTP1TunnelKeepsDataReadWithResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	common.Must(err)
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
			return
		}
		// A proxy relaying a server-first protocol may deliver the greeting in the same segment as the 200.
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n220 smtp ready\r\n"))
		io.Copy(io.Discard, conn)
	}()

	dest := net.TCPDestination(net.LocalHostIP, net.Port(listener.Addr().(*net.TCPAddr).Port))
	conn, err := setUpHTTPTunnel(context.Background(), dest, "example.com:25", nil, testDialer{}, nil, nil)
	common.Must(err)
	defer conn.Close()

	common.Must(conn.SetReadDeadline(time.Now().Add(5 * time.Second)))
	greeting := make([]byte, 64)
	n, err := conn.Read(greeting)
	if err != nil {
		t.Fatal("greeting sent with the CONNECT response was lost: ", err)
	}
	if string(greeting[:n]) != "220 smtp ready\r\n" {
		t.Fatalf("unexpected greeting: %q", greeting[:n])
	}
}
