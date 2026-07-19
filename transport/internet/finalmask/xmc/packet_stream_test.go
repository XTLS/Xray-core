package xmc

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestPacketStreamUsesPlainFraming(t *testing.T) {
	payload := []byte("hello")
	var wire bytes.Buffer
	stream := newPacketStream(bytes.NewReader(nil), &wire, true)

	written, err := stream.Write(payload)
	if err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if written != len(payload) {
		t.Fatalf("written = %d, want %d", written, len(payload))
	}
	wantOutbound := []byte{0x0f, 0x02, 0x08, 'x', 'm', 'c', ':', 'd', 'a', 't', 'a', 'h', 'e', 'l', 'l', 'o'}
	if !bytes.Equal(wire.Bytes(), wantOutbound) {
		t.Fatalf("wire frame = %x, want %x", wire.Bytes(), wantOutbound)
	}

	wantInbound := append([]byte(nil), wantOutbound...)
	wantInbound[1] = configurationClientboundCustomPayload
	reader := newPacketStream(bytes.NewReader(wantInbound), io.Discard, true)
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(reader, got); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
}

func TestPacketStreamRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const password = "packet-stream-shared-key"
	privateKey, publicKey := deriveTestRSAKey(t, password)
	profiles := []loginProfile{testLoginProfile("packet_user")}
	clientPayload := bytes.Repeat([]byte("client-payload-"), 5000)
	serverPayload := bytes.Repeat([]byte("server-payload-"), 5000)
	serverDone := make(chan error, 1)

	go func() {
		rawConn, acceptErr := ln.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer rawConn.Close()

		server, wrapErr := wrapConnServer(rawConn, profiles, password, privateKey, publicKey)
		if wrapErr != nil {
			serverDone <- wrapErr
			return
		}
		got := make([]byte, len(clientPayload))
		if _, readErr := io.ReadFull(server, got); readErr != nil {
			serverDone <- readErr
			return
		}
		if !bytes.Equal(got, clientPayload) {
			serverDone <- io.ErrUnexpectedEOF
			return
		}
		_, writeErr := server.Write(serverPayload)
		serverDone <- writeErr
	}()

	rawClient, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer rawClient.Close()

	client, err := newClientConn(rawClient, profiles, password, publicKey, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Write(clientPayload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	got := make([]byte, len(serverPayload))
	if _, err = io.ReadFull(client, got); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if !bytes.Equal(got, serverPayload) {
		t.Fatal("server payload mismatch")
	}
	if err = <-serverDone; err != nil {
		t.Fatalf("server: %v", err)
	}
}
