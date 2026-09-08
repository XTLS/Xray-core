package hysteria

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/apernet/quic-go"
)

// TestInterConnConcurrentWriteAndClose reaches the ordinary client UDP session
// lifecycle: udp creates InterConn and its Close callback takes the manager
// lock before calling udpSessionManager.close. A user write and that close have
// no synchronization around InterConn.closed in the baseline.
func TestInterConnConcurrentWriteAndClose(t *testing.T) {
	client, _ := newLocalQUICPair(t)
	manager := &udpSessionManager{
		conn: client,
		m:    make(map[uint32]*InterConn),
	}
	conn, err := manager.udp()
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	writeDone := make(chan struct{})
	closeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		<-start
		for range 10000 {
			// Write overwrites the first four bytes with the session ID.
			_, _ = conn.Write(make([]byte, 4))
		}
	}()
	go func() {
		defer close(closeDone)
		<-start
		_ = conn.Close()
	}()
	close(start)
	<-writeDone
	<-closeDone
}

// TestUDPSessionManagerConcurrentCleanupAndShutdown uses a connected local
// QUIC pair. Closing the peer makes run leave ReceiveDatagram and set closed,
// while clean observes the same field on its regular cleanup tick. It exercises
// the baseline's production goroutine bodies; it does not claim user-visible
// impact.
func TestUDPSessionManagerConcurrentCleanupAndShutdown(t *testing.T) {
	client, server := newLocalQUICPair(t)
	manager := &udpSessionManager{
		conn: server,
		m:    make(map[uint32]*InterConn),
	}

	runDone := make(chan struct{})
	cleanDone := make(chan struct{})
	go func() {
		manager.run()
		close(runDone)
	}()
	go func() {
		manager.clean()
		close(cleanDone)
	}()

	// Let clean reach its first production ticker read before closing the peer.
	time.Sleep(idleCleanupInterval + 100*time.Millisecond)
	if err := client.CloseWithError(closeErrCodeOK, ""); err != nil {
		t.Fatal(err)
	}

	awaitTestGoroutine(t, runDone)
	awaitTestGoroutine(t, cleanDone)
}

func awaitTestGoroutine(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Hysteria session goroutine did not stop")
	}
}

func newLocalQUICPair(t *testing.T) (*quic.Conn, *quic.Conn) {
	t.Helper()
	certificate := newTestCertificate(t)
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"hysteria-race"},
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan *quic.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	client, err := quic.DialAddr(context.Background(), listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"hysteria-race"},
	}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(closeErrCodeOK, "") })

	select {
	case server := <-accepted:
		t.Cleanup(func() { _ = server.CloseWithError(closeErrCodeOK, "") })
		return client, server
	case err := <-acceptErr:
		t.Fatal(err)
		return nil, nil
	case <-time.After(3 * time.Second):
		t.Fatal("timed out accepting local QUIC connection")
		return nil, nil
	}
}

func newTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "hysteria-race"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Minute),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
