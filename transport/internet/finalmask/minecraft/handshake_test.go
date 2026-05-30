package minecraft

import (
	"bytes"
	"crypto/x509"
	"net"
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

func TestHandshakeSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	password := "super-secure-shared-key-12345"
	usernames := []string{"test_user"}
	privateKey, publicKey := deriveTestRSAKey(t, password)

	go func() {
		rawConn, err := ln.Accept()
		if err != nil {
			return
		}
		defer rawConn.Close()

		server, err := wrapConnServer(rawConn, password, privateKey, publicKey)
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

	client, err := newClientConn(clientRaw, usernames, password, publicKey, "localhost", uint16(ln.Addr().(*net.TCPAddr).Port))
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
	usernames := []string{"test_user"}
	serverPrivateKey, serverPublicKey := deriveTestRSAKey(t, serverPassword)
	_, clientPublicKey := deriveTestRSAKey(t, clientPassword)

	go func() {
		rawConn, err := ln.Accept()
		if err != nil {
			return
		}
		defer rawConn.Close()

		server, err := wrapConnServer(rawConn, serverPassword, serverPrivateKey, serverPublicKey)
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

	client, err := newClientConn(clientRaw, usernames, clientPassword, clientPublicKey, "localhost", uint16(ln.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Wait briefly or just perform write/read
	_ = clientRaw.SetDeadline(time.Now().Add(100 * time.Millisecond))

	_, err = client.Write([]byte("hello server"))
	if err == nil {
		// Try to read too
		buf := make([]byte, 1024)
		_, _ = client.Read(buf)
	}

	// Check if we lost connection or received error
	t.Log("Handshake mismatch tested")
}
