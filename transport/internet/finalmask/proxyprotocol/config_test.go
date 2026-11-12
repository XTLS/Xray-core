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

func TestClientHeader(t *testing.T) {
	for _, version := range []uint32{0, 1, 2} {
		for _, sourceIP := range []string{"", "198.51.100.7", "2001:db8::7"} {
			t.Run(fmt.Sprintf("version=%d/source=%s", version, sourceIP), func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				ctx := context.Background()
				if sourceIP != "" {
					ctx = session.ContextWithInbound(ctx, &session.Inbound{
						Source: net.TCPDestination(net.ParseAddress(sourceIP), 12345),
					})
				}
				fm := finalmask.NewFinalMask([]finalmask.TCPMask{&Config{Version: version}}, nil,
					func(ctx context.Context, dest net.Destination) (net.Conn, error) {
						return net.Dial("tcp", dest.NetAddr())
					}, nil, nil, nil)
				client, err := fm.DialTCP(ctx, net.DestinationFromAddr(listener.Addr()))
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				raw, err := listener.Accept()
				if err != nil {
					t.Fatal(err)
				}
				server := proxyproto.NewConn(raw, proxyproto.WithPolicy(proxyproto.REQUIRE))
				defer server.Close()
				deadline := time.Now().Add(5 * time.Second)
				if err := client.SetDeadline(deadline); err != nil {
					t.Fatal(err)
				}
				if err := server.SetDeadline(deadline); err != nil {
					t.Fatal(err)
				}
				header := server.ProxyHeader()
				wantVersion := byte(version)
				if wantVersion == 0 {
					wantVersion = 2
				}
				if header == nil || header.Version != wantVersion || header.Command != proxyproto.PROXY {
					t.Fatalf("unexpected PROXY header: %v", header)
				}
				wantSource := client.LocalAddr()
				if sourceIP != "" {
					wantSource = &net.TCPAddr{IP: net.ParseIP(sourceIP), Port: 12345}
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
