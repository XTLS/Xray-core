package xmc

import (
	"bytes"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"
)

func TestHandshakeWithBidirectionalPadding(t *testing.T) {
	t.Run("pipe", func(t *testing.T) {
		client, server := net.Pipe()
		testHandshakeWithPadding(t, client, server, 64*1024)
	})
	t.Run("tcp", func(t *testing.T) {
		listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		server, err := listener.AcceptTCP()
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		for _, conn := range []*net.TCPConn{client, server} {
			if err := conn.SetWriteBuffer(16 * 1024); err != nil {
				t.Fatal(err)
			}
			if err := conn.SetReadBuffer(64 * 1024); err != nil {
				t.Fatal(err)
			}
		}
		testHandshakeWithPadding(t, client, server, maxPaddingTurnLength)
	})
}

func testHandshakeWithPadding(t *testing.T, clientRaw, serverRaw net.Conn, length int64) {
	t.Helper()
	defer clientRaw.Close()
	defer serverRaw.Close()

	key, err := DeriveRSAKey("padding-regression")
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	profiles := []loginProfile{{
		Username: "TestUser",
		Properties: loginProperties{{
			Name:      "textures",
			Value:     "texture",
			Signature: "signature",
			Signed:    true,
		}},
	}}
	padding := []*Padding{
		{Direction: 1, LengthMin: length, LengthMax: length},
		{Direction: 2, LengthMin: length, LengthMax: length},
	}
	paddingSchedule, err := paddingScheduleFromConfig(padding)
	if err != nil {
		t.Fatal(err)
	}
	client, err := newClientConn(clientRaw, profiles, "password", publicKey, "localhost", paddingSchedule, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := wrapConnServer(serverRaw, profiles, "password", x509.MarshalPKCS1PrivateKey(key), publicKey, paddingSchedule, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, conn := range []net.Conn{client, server} {
		if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}

	results := make(chan error, 2)
	go func() { results <- client.handshake() }()
	go func() { results <- server.handshake() }()
	for range 2 {
		if err := <-results; err != nil {
			t.Errorf("handshake: %v", err)
		}
	}
	if t.Failed() {
		return
	}

	// Both startup readers can already be waiting for the next packet. The
	// first proxy payload in either direction must survive the handoff.
	for _, pair := range [][2]net.Conn{{client, server}, {server, client}} {
		want := bytes.Repeat([]byte("proxy payload"), 4096)
		go func() {
			_, err := pair[0].Write(want)
			results <- err
		}()
		got := make([]byte, len(want))
		if _, err := io.ReadFull(pair[1], got); err != nil {
			t.Fatal(err)
		}
		if err := <-results; err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("proxy payload changed after startup padding")
		}
	}
}
