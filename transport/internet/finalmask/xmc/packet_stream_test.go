package xmc

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestPacketModeRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const password = "packet-mode-shared-key"
	privateKey, publicKey := deriveTestRSAKey(t, password)
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

		server, wrapErr := wrapConnServer(rawConn, password, privateKey, publicKey, modePacket)
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

	client, err := newClientConn(rawClient, []string{"packet_user"}, password, publicKey, "localhost", modePacket)
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

func TestOfflineUUIDVersion3(t *testing.T) {
	var got UUID
	generateOfflineUUID(&got, "Steve")
	want := UUID{0x56, 0x27, 0xdd, 0x98, 0xe6, 0xbe, 0x3c, 0x21, 0xb8, 0xa8, 0xe9, 0x23, 0x44, 0x18, 0x36, 0x41}
	if got != want {
		t.Fatalf("offline UUID = %x, want %x", got, want)
	}
}

func TestPacketModeRejectsInvalidMode(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	if _, err := newClientConn(left, []string{"user"}, "password", []byte{1}, "localhost", "invalid"); err == nil {
		t.Fatal("expected invalid mode to be rejected")
	}
}
