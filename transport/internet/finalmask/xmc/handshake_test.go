package xmc

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"net"
	"sync"
	"testing"
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
		TexturesValue:     "test-textures-value",
		TexturesSignature: "test-textures-signature",
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
