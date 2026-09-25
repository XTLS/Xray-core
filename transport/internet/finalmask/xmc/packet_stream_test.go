package xmc

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
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
	for name, padding := range map[string][]*Padding{
		"default": nil,
		"single":  {{LengthMin: 3, LengthMax: 3}},
		"even":    {{LengthMin: 127, LengthMax: 129}, {LengthMin: 16383, LengthMax: 16385}},
		"odd":     {{LengthMin: 3, LengthMax: 3}, {LengthMin: 1, LengthMax: 1}, {LengthMin: 32768, LengthMax: 32768}},
	} {
		t.Run(name, func(t *testing.T) { testPacketStreamRoundTrip(t, padding) })
	}
}

func testPacketStreamRoundTrip(t *testing.T, padding []*Padding) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const password = "packet-stream-shared-key"
	privateKey, publicKey := deriveTestRSAKey(t, password)
	profile := testLoginProfile("packet_user")
	config := &Config{
		Password: password, RsaPrivateKey: privateKey, RsaPublicKey: publicKey,
		Hostname: "localhost", Padding: padding,
		Profiles: []*Profile{{
			Username: profile.Username, Uuid: profile.UUID[:],
			TexturesValue: profile.TexturesValue, TexturesSignature: profile.TexturesSignature,
		}},
	}
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
		if err := rawConn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			serverDone <- err
			return
		}

		server, wrapErr := config.WrapConnServer(rawConn)
		if wrapErr != nil {
			serverDone <- wrapErr
			return
		}
		defer server.Close()
		if len(padding) > 0 && len(server.(*serverConn).paddingSchedule) != len(padding) {
			t.Error("server did not use configured padding")
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
	if err := rawClient.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}

	client, err := config.WrapConnClient(rawClient)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if len(padding) > 0 && len(client.(*clientConn).paddingSchedule) != len(padding) {
		t.Fatal("client did not use configured padding")
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
