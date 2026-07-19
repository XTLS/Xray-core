package xmc

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func deriveTestRSAKey(t *testing.T, password string) ([]byte, []byte) {
	t.Helper()

	key, err := DeriveRSAKey(password)
	if err != nil {
		t.Fatalf("failed to derive rsa key: %v", err)
	}

	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	return x509.MarshalPKCS1PrivateKey(key), publicKey
}

func testLoginProfile(username string) loginProfile {
	profile := loginProfile{
		Username:          username,
		TexturesValue:     strings.Repeat("texture-value-", 40),
		TexturesSignature: strings.Repeat("texture-signature-", 24),
	}
	digest := sha256.Sum256([]byte(username))
	copy(profile.UUID[:], digest[:16])
	profile.UUID[6] = (profile.UUID[6] & 0x0f) | 0x40
	profile.UUID[8] = (profile.UUID[8] & 0x3f) | 0x80
	return profile
}

func TestHandshakeSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	password := "super-secure-shared-key-12345"
	profiles := []loginProfile{testLoginProfile("test_user")}
	privateKey, publicKey := deriveTestRSAKey(t, password)

	go func() {
		rawConn, err := ln.Accept()
		if err != nil {
			return
		}
		defer rawConn.Close()

		server, err := wrapConnServer(rawConn, profiles, password, privateKey, publicKey)
		if err != nil {
			t.Errorf("failed to wrap server: %v", err)
			return
		}

		buf := make([]byte, 1024)
		n, err := server.Read(buf)
		if err != nil {
			t.Errorf("server read error: %v", err)
			return
		}

		if !bytes.Equal(buf[:n], []byte("hello server")) {
			t.Errorf("unexpected payload from client: %s", string(buf[:n]))
			return
		}

		_, err = server.Write([]byte("hello client"))
		if err != nil {
			t.Errorf("server write error: %v", err)
			return
		}
	}()

	clientRaw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer clientRaw.Close()

	client, err := newClientConn(clientRaw, profiles, password, publicKey, "localhost")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, err = client.Write([]byte("hello server"))
	if err != nil {
		t.Fatalf("client write error: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("client read error: %v", err)
	}

	if !bytes.Equal(buf[:n], []byte("hello client")) {
		t.Errorf("unexpected payload from server: %s", string(buf[:n]))
	}
}

func TestHandshakePasswordMismatch(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	clientPassword := "client-secret-123"
	serverPassword := "server-secret-456"
	profiles := []loginProfile{testLoginProfile("test_user")}
	serverPrivateKey, serverPublicKey := deriveTestRSAKey(t, serverPassword)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		rawConn, err := ln.Accept()
		if err != nil {
			return
		}
		defer rawConn.Close()

		server, err := wrapConnServer(rawConn, profiles, serverPassword, serverPrivateKey, serverPublicKey)
		if err != nil {
			// Wrapping is synchronous and shouldn't fail initially simply because key derivation works with any string
			t.Logf("wrapped server: %v", err)
		}

		// When client sends data, handshake happens and should fail
		buf := make([]byte, 1024)
		_, err = server.Read(buf)
		if err == nil {
			t.Errorf("expected handshake to fail due to password mismatch, but it succeeded")
		} else {
			t.Logf("server read failed as expected: %v", err)
		}
	}()

	clientRaw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer clientRaw.Close()

	client, err := newClientConn(clientRaw, profiles, clientPassword, serverPublicKey, "localhost")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	err = client.handshake()
	if err == nil {
		t.Fatal("expected client handshake to fail due to password mismatch")
	}

	wg.Wait()

	// Check if we lost connection or received error
	t.Log("Handshake mismatch tested")
}

func TestHandshakeNetPipeWithKeepAlive(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	const password = "net-pipe-shared-key"
	profiles := []loginProfile{testLoginProfile("pipe_user")}
	privateKey, publicKey := deriveTestRSAKey(t, password)
	serverDone := make(chan error, 1)

	go func() {
		server, err := wrapConnServer(serverRaw, profiles, password, privateKey, publicKey)
		if err != nil {
			serverDone <- err
			return
		}

		request := make([]byte, len("hello server"))
		if _, err = io.ReadFull(server, request); err != nil {
			serverDone <- fmt.Errorf("read request: %w", err)
			return
		}
		if string(request) != "hello server" {
			serverDone <- fmt.Errorf("unexpected request: %q", request)
			return
		}

		followupDone := make(chan error, 1)
		go func() {
			followup := make([]byte, len("after keepalive"))
			_, readErr := io.ReadFull(server, followup)
			if readErr == nil && string(followup) != "after keepalive" {
				readErr = fmt.Errorf("unexpected followup: %q", followup)
			}
			followupDone <- readErr
		}()

		if err = server.packet.writeKeepAlive(Long(42)); err != nil {
			serverDone <- fmt.Errorf("write keep-alive: %w", err)
			return
		}
		if _, err = server.Write([]byte("hello client")); err != nil {
			serverDone <- fmt.Errorf("write response: %w", err)
			return
		}
		serverDone <- <-followupDone
	}()

	client, err := newClientConn(clientRaw, profiles, password, publicKey, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Write([]byte("hello server")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	response := make([]byte, len("hello client"))
	if _, err = io.ReadFull(client, response); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(response) != "hello client" {
		t.Fatalf("unexpected response: %q", response)
	}
	if _, err = client.Write([]byte("after keepalive")); err != nil {
		t.Fatalf("write followup: %v", err)
	}

	select {
	case err = <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("net.Pipe handshake timed out")
	}
}

func TestStatusQueryUnaffected(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	const password = "status-shared-key"
	profiles := []loginProfile{testLoginProfile("status_user")}
	privateKey, publicKey := deriveTestRSAKey(t, password)
	serverDone := make(chan error, 1)
	go func() {
		server, err := wrapConnServer(serverRaw, profiles, password, privateKey, publicKey)
		if err == nil {
			err = server.handshake()
		}
		serverDone <- err
	}()

	protocolVersion := Varint(775)
	serverAddress := String("localhost")
	serverPort := UnsignedShort(25565)
	nextState := Varint(1)
	if err := writePacket(clientRaw, 0x00, &protocolVersion, &serverAddress, &serverPort, &nextState); err != nil {
		t.Fatal(err)
	}
	if err := writePacket(clientRaw, 0x00); err != nil {
		t.Fatal(err)
	}
	response, err := readPacket(clientRaw)
	if err != nil {
		t.Fatal(err)
	}
	if response.packetID != 0x00 {
		t.Fatalf("status packet id = %d", response.packetID)
	}
	var responseJSON String
	if err = response.readFields(&responseJSON); err != nil {
		t.Fatal(err)
	}
	if string(responseJSON) != statusResponse {
		t.Fatalf("status response = %q", responseJSON)
	}

	payload := Long(0x0102030405060708)
	if err = writePacket(clientRaw, 0x01, &payload); err != nil {
		t.Fatal(err)
	}
	pong, err := readPacket(clientRaw)
	if err != nil {
		t.Fatal(err)
	}
	var receivedPayload Long
	if pong.packetID != 0x01 {
		t.Fatalf("pong packet id = %d", pong.packetID)
	}
	if err = pong.readFields(&receivedPayload); err != nil {
		t.Fatal(err)
	}
	if receivedPayload != payload {
		t.Fatalf("pong payload = %x", receivedPayload)
	}

	select {
	case err = <-serverDone:
		if err == nil || !strings.Contains(err.Error(), "ping") {
			t.Fatalf("server error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("status handshake timed out")
	}
}

func TestClientHandshakeHonorsCallerDeadline(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	const password = "deadline-shared-key"
	profiles := []loginProfile{testLoginProfile("deadline_user")}
	_, publicKey := deriveTestRSAKey(t, password)
	client, err := newClientConn(clientRaw, profiles, password, publicKey, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if err = client.SetDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	_, err = client.Write([]byte("blocked"))
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("error = %v, want network timeout", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("caller deadline took %s", elapsed)
	}
}

func TestClientCloseInterruptsHandshake(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer serverRaw.Close()

	const password = "close-shared-key"
	profiles := []loginProfile{testLoginProfile("close_user")}
	_, publicKey := deriveTestRSAKey(t, password)
	client, err := newClientConn(clientRaw, profiles, password, publicKey, "localhost")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, writeErr := client.Write([]byte("blocked"))
		done <- writeErr
	}()
	time.Sleep(20 * time.Millisecond)
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err = <-done:
		if err == nil {
			t.Fatal("handshake unexpectedly succeeded after close")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not interrupt handshake")
	}
}

func TestValidateLoginAcknowledgedPacketRejectsData(t *testing.T) {
	if err := validateLoginAcknowledgedPacket(&mcPacket{packetID: 0x03}); err != nil {
		t.Fatalf("valid login acknowledged packet: %v", err)
	}
	if err := validateLoginAcknowledgedPacket(&mcPacket{packetID: 0x03, data: []byte{0x00}}); err == nil {
		t.Fatal("login acknowledged packet with trailing data was accepted")
	}
}
