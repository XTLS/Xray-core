package custom

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDSLTCPHandshakeReusesCapturedValue(t *testing.T) {
	cfg := &TCPConfig{
		Clients: []*TCPSequence{
			{
				Sequence: []*TCPItem{
					{
						Rand:    2,
						RandMin: 0x2A,
						RandMax: 0x2A,
						Save:    "txid",
					},
				},
			},
		},
		Servers: []*TCPSequence{
			{
				Sequence: []*TCPItem{
					{
						Var: "txid",
					},
				},
			},
		},
	}

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	client, err := cfg.WrapConnClient(clientRaw)
	if err != nil {
		t.Fatal(err)
	}
	server, err := cfg.WrapConnServer(serverRaw)
	if err != nil {
		t.Fatal(err)
	}

	_ = client.SetDeadline(time.Now().Add(time.Second))
	_ = server.SetDeadline(time.Now().Add(time.Second))

	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("payload"))
		writeErr <- err
	}()

	buf := make([]byte, len("payload"))
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "payload" {
		t.Fatalf("unexpected payload: %q", buf)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
}

func TestDSLTCPClientRejectsMismatchedResponseSequence(t *testing.T) {
	clientCfg := &TCPConfig{
		Clients: []*TCPSequence{
			{
				Sequence: []*TCPItem{
					{
						Rand:    2,
						RandMin: 0x2A,
						RandMax: 0x2A,
						Save:    "txid",
					},
				},
			},
		},
		Servers: []*TCPSequence{
			{
				Sequence: []*TCPItem{
					{
						Var: "txid",
					},
				},
			},
		},
	}
	serverCfg := &TCPConfig{
		Clients: []*TCPSequence{
			{
				Sequence: []*TCPItem{
					{
						Rand: 2,
						Save: "txid",
					},
				},
			},
		},
		Servers: []*TCPSequence{
			{
				Sequence: []*TCPItem{
					{
						Packet: []byte{0x01, 0x02},
					},
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
		_, err := client.Write([]byte("payload"))
		writeErr <- err
	}()

	buf := make([]byte, len("payload"))
	_, readErr := server.Read(buf)

	if err := <-writeErr; err == nil || !strings.Contains(err.Error(), "header auth failed") {
		t.Fatalf("expected client auth failure, got %v", err)
	}
	if readErr == nil {
		t.Fatal("expected server read to fail")
	}
	if ne, ok := readErr.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("expected server timeout after client auth failure, got %v", readErr)
	}
}
