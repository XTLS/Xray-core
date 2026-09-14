package finalmask_test

import (
	"bytes"
	"context"
	"io"
	gonet "net"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/finalmask/header/custom"
)

func mustSendRecvTcp(
	t *testing.T,
	from net.Conn,
	to net.Conn,
	msg []byte,
) {
	t.Helper()

	go func() {
		_, err := from.Write(msg)
		if err != nil {
			t.Error(err)
		}
	}()

	buf := make([]byte, 1024)
	n, err := io.ReadFull(to, buf[:len(msg)])
	if err != nil {
		t.Fatal(err)
	}

	if n != len(msg) {
		t.Fatalf("unexpected size: %d", n)
	}

	if !bytes.Equal(buf[:n], msg) {
		t.Fatalf("unexpected data %q", buf[:n])
	}
}

type layerMaskTcp struct {
	name string
	mask finalmask.TCPMask
}

type failingWrapMask struct{}

func (failingWrapMask) TCP() {}
func (f failingWrapMask) WrapConnClient(conn net.Conn, dest net.Destination, dialer *finalmask.Dialer) (net.Conn, error) {
	return conn, nil
}
func (f failingWrapMask) WrapConnServer(conn net.Conn) (net.Conn, error) {
	return nil, io.ErrClosedPipe
}

func TestConnReadWrite(t *testing.T) {
	cases := []layerMaskTcp{
		{
			name: "custom",
			mask: &custom.TCPConfig{
				Clients: []*custom.TCPSequence{
					{
						Sequence: []*custom.TCPItem{
							{
								Packet: []byte{1},
							},
							{
								Rand: 1,
							},
						},
					},
				},
				Servers: []*custom.TCPSequence{
					{
						Sequence: []*custom.TCPItem{
							{
								Packet: []byte{2},
							},
							{
								Rand: 1,
							},
						},
					},
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mask := c.mask

			dialTCP := func(ctx context.Context, dest net.Destination) (net.Conn, error) {
				return net.Dial("tcp", dest.NetAddr())
			}
			listen := func(ctx context.Context, addr net.Addr) (net.Listener, error) {
				return net.Listen("tcp", addr.String())
			}
			finalMask := finalmask.NewFinalMask([]finalmask.TCPMask{mask}, nil, dialTCP, listen, nil, nil)

			listener, err := finalMask.Listen(context.Background(), &net.TCPAddr{IP: net.LocalHostIP.IP()})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			client, err := finalMask.DialTCP(context.Background(), net.TCPDestination(net.IPAddress(listener.Addr().(*net.TCPAddr).IP), net.Port(listener.Addr().(*net.TCPAddr).Port)))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()

			server, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()

			_ = client.SetDeadline(time.Now().Add(time.Second))
			_ = server.SetDeadline(time.Now().Add(time.Second))

			mustSendRecvTcp(t, client, server, []byte("client -> server"))
			mustSendRecvTcp(t, server, client, []byte("server -> client"))

			mustSendRecvTcp(t, client, server, []byte{})
			mustSendRecvTcp(t, server, client, []byte{})
		})
	}
}

func TestTCPcustomStaticHandshakeRoundTrip(t *testing.T) {
	cfg := &custom.TCPConfig{
		Clients: []*custom.TCPSequence{
			{
				Sequence: []*custom.TCPItem{
					{Packet: []byte("cli")},
					{Rand: 2, RandMin: 0x10, RandMax: 0x20},
				},
			},
		},
		Servers: []*custom.TCPSequence{
			{
				Sequence: []*custom.TCPItem{
					{Packet: []byte("srv")},
					{Rand: 1, RandMin: 0x30, RandMax: 0x40},
				},
			},
		},
	}

	dialTCP := func(ctx context.Context, dest net.Destination) (net.Conn, error) {
		return net.Dial("tcp", dest.NetAddr())
	}
	listen := func(ctx context.Context, addr net.Addr) (net.Listener, error) {
		return net.Listen("tcp", addr.String())
	}
	finalMask := finalmask.NewFinalMask([]finalmask.TCPMask{cfg}, nil, dialTCP, listen, nil, nil)

	listener, err := finalMask.Listen(context.Background(), &net.TCPAddr{IP: net.LocalHostIP.IP()})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	client, err := finalMask.DialTCP(context.Background(), net.TCPDestination(net.IPAddress(listener.Addr().(*net.TCPAddr).IP), net.Port(listener.Addr().(*net.TCPAddr).Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	_ = client.SetDeadline(time.Now().Add(time.Second))
	_ = server.SetDeadline(time.Now().Add(time.Second))

	mustSendRecvTcp(t, client, server, []byte("custom tcp payload"))
	mustSendRecvTcp(t, server, client, []byte("custom tcp response"))
}

func TestTCPcustomClientRejectsMismatchedServerSequence(t *testing.T) {
	clientCfg := &custom.TCPConfig{
		Clients: []*custom.TCPSequence{
			{
				Sequence: []*custom.TCPItem{
					{Packet: []byte{0x01}},
				},
			},
		},
		Servers: []*custom.TCPSequence{
			{
				Sequence: []*custom.TCPItem{
					{Packet: []byte{0x02}},
				},
			},
		},
	}
	serverCfg := &custom.TCPConfig{
		Clients: []*custom.TCPSequence{
			{
				Sequence: []*custom.TCPItem{
					{Packet: []byte{0x01}},
				},
			},
		},
		Servers: []*custom.TCPSequence{
			{
				Sequence: []*custom.TCPItem{
					{Packet: []byte{0x03}},
				},
			},
		},
	}

	clientRaw, serverRaw := gonet.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	client, err := clientCfg.WrapConnClient(clientRaw, net.Destination{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := serverCfg.WrapConnServer(serverRaw)
	if err != nil {
		t.Fatal(err)
	}

	_ = client.SetDeadline(time.Now().Add(time.Second))
	_ = server.SetDeadline(time.Now().Add(time.Second))

	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("boom"))
		writeErr <- err
	}()

	buf := make([]byte, 4)
	_, readErr := server.Read(buf)

	if err := <-writeErr; err == nil || !strings.Contains(err.Error(), "header auth failed") {
		t.Fatalf("expected client header auth failure, got %v", err)
	}
	if readErr == nil {
		t.Fatal("expected server read to fail")
	}
	if ne, ok := readErr.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("expected server timeout after client auth failure, got %v", readErr)
	}
}

func TestTCPWrapListenerRejectsImmediateWrapErrors(t *testing.T) {
	dialTCP := func(ctx context.Context, dest net.Destination) (net.Conn, error) {
		return net.Dial("tcp", dest.NetAddr())
	}
	listen := func(ctx context.Context, addr net.Addr) (net.Listener, error) {
		return net.Listen("tcp", addr.String())
	}
	finalMask := finalmask.NewFinalMask([]finalmask.TCPMask{failingWrapMask{}}, nil, dialTCP, listen, nil, nil)

	listener, err := finalMask.Listen(context.Background(), &net.TCPAddr{IP: net.LocalHostIP.IP()})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		conn, err := listener.Accept()
		accepted <- struct {
			conn net.Conn
			err  error
		}{conn: conn, err: err}
	}()

	client, err := finalMask.DialTCP(context.Background(), net.TCPDestination(net.IPAddress(listener.Addr().(*net.TCPAddr).IP), net.Port(listener.Addr().(*net.TCPAddr).Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	_ = client.SetDeadline(time.Now().Add(time.Second))

	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("payload"))
		writeErr <- err
	}()

	result := <-accepted
	if result.err == nil {
		if result.conn != nil {
			result.conn.Close()
		}
		t.Fatal("expected wrapped listener accept to fail")
	}
	if result.conn != nil {
		result.conn.Close()
		t.Fatalf("expected no raw conn on wrapped listener failure, got %T", result.conn)
	}
	<-writeErr
}
