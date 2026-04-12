package finalmask_test

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"

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
	mask finalmask.Tcpmask
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

			maskManager := finalmask.NewTcpmaskManager([]finalmask.Tcpmask{mask})

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}

			client, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}

			client, err = maskManager.WrapConnClient(client)
			if err != nil {
				t.Fatal(err)
			}

			server, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}

			server, err = maskManager.WrapConnServer(server)
			if err != nil {
				t.Fatal(err)
			}

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
	maskManager := finalmask.NewTcpmaskManager([]finalmask.Tcpmask{cfg})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	clientRaw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientRaw.Close()

	serverRaw, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer serverRaw.Close()

	client, err := maskManager.WrapConnClient(clientRaw)
	if err != nil {
		t.Fatal(err)
	}
	server, err := maskManager.WrapConnServer(serverRaw)
	if err != nil {
		t.Fatal(err)
	}

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

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	client, err := clientCfg.WrapConnClient(clientRaw)
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
