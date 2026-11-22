package proxyprotocol

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func TestHeaderFromTCPSourceToUDPDestination(t *testing.T) {
	source := &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 12345}
	destination := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 443}
	header := headerFromAddrs(2, source, destination)
	from, to, ok := header.UDPAddrs()
	if header.Command != proxyproto.PROXY || header.TransportProtocol != proxyproto.UDPv4 || !ok {
		t.Fatalf("expected a UDP PROXY header, got %v", header)
	}
	if from.String() != source.String() || to.String() != destination.String() {
		t.Fatalf("addresses = %v -> %v, want %v -> %v", from, to, source, destination)
	}
}

func TestClientHeader(t *testing.T) {
	const sourcePort = 12345
	sources := []net.Destination{
		{},
		net.TCPDestination(net.ParseAddress("198.51.100.7"), sourcePort),
		net.TCPDestination(net.ParseAddress("2001:db8::7"), sourcePort),
		net.UDPDestination(net.ParseAddress("198.51.100.7"), sourcePort),
		net.UDPDestination(net.ParseAddress("2001:db8::7"), sourcePort),
	}
	for _, version := range []uint32{0, 1, 2} {
		for _, source := range sources {
			t.Run(fmt.Sprintf("version=%d/source=%s", version, source), func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				ctx := context.Background()
				if source.IsValid() {
					ctx = session.ContextWithInbound(ctx, &session.Inbound{
						Source: source,
					})
				}
				fm := finalmask.NewFinalMask([]finalmask.TCPMask{&Config{Version: version}}, nil,
					func(ctx context.Context, dest net.Destination) (net.Conn, error) {
						return net.Dial("tcp", dest.NetAddr())
					}, func(ctx context.Context, addr net.Addr) (net.Listener, error) {
						return listener, nil
					}, nil, nil)
				maskedListener, err := fm.Listen(context.Background(), listener.Addr())
				if err != nil {
					t.Fatal(err)
				}
				client, err := fm.DialTCP(ctx, net.DestinationFromAddr(listener.Addr()))
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				server, err := maskedListener.Accept()
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				deadline := time.Now().Add(5 * time.Second)
				if err := client.SetDeadline(deadline); err != nil {
					t.Fatal(err)
				}
				if err := server.SetDeadline(deadline); err != nil {
					t.Fatal(err)
				}
				proxyConn, ok := server.(*proxyproto.Conn)
				if !ok {
					t.Fatalf("server connection type = %T, want *proxyproto.Conn", server)
				}
				header := proxyConn.ProxyHeader()
				wantVersion := byte(version)
				if wantVersion == 0 {
					wantVersion = 2
				}
				if header == nil || header.Version != wantVersion || header.Command != proxyproto.PROXY {
					t.Fatalf("unexpected PROXY header: %v", header)
				}
				wantSource := client.LocalAddr()
				if source.IsValid() {
					wantSource = &net.TCPAddr{IP: source.Address.IP(), Port: sourcePort}
				}
				if server.RemoteAddr().String() != wantSource.String() || server.LocalAddr().String() != listener.Addr().String() {
					t.Fatalf("addresses = %v -> %v, want %v -> %v", server.RemoteAddr(), server.LocalAddr(), wantSource, listener.Addr())
				}
				for _, pair := range [][2]net.Conn{{client, server}, {client, server}, {server, client}} {
					const payload = "application payload"
					if _, err := io.WriteString(pair[0], payload); err != nil {
						t.Fatal(err)
					}
					data := make([]byte, len(payload))
					if _, err := io.ReadFull(pair[1], data); err != nil {
						t.Fatal(err)
					}
					if string(data) != payload {
						t.Fatalf("payload = %q", data)
					}
				}
			})
		}
	}
}
