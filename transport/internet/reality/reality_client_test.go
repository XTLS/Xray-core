package reality

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

type closeTrackingConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeTrackingConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func TestUClientCamouflageOwnsConnection(t *testing.T) {
	// Isolate the test root CA from other tests and the host trust store.
	if os.Getenv("XRAY_TEST_REALITY_FALLBACK_HELPER") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestUClientCamouflageOwnsConnection$", "-test.timeout=20s")
		cmd.Env = append(os.Environ(), "XRAY_TEST_REALITY_FALLBACK_HELPER=1", "GODEBUG=x509usefallbackroots=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("camouflage subprocess failed: %v\n%s", err, output)
		}
		return
	}

	requestStarted := make(chan struct{})
	releaseResponse := make(chan struct{})
	responseWritten := make(chan error, 1)
	var started sync.Once
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started.Do(func() { close(requestStarted) })
		select {
		case <-releaseResponse:
			_, err := w.Write([]byte("camouflage"))
			responseWritten <- err
		case <-r.Context().Done():
			responseWritten <- r.Context().Err()
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	var release sync.Once
	defer release.Do(func() { close(releaseResponse) })

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	x509.SetFallbackRoots(roots)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr := server.Listener.Addr().(*net.TCPAddr)
	raw, err := net.DialTimeout("tcp", addr.String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn := &closeTrackingConn{Conn: raw}
	defer conn.Close()

	config := &Config{
		ServerName:  "example.com",
		Fingerprint: "chrome",
		PublicKey:   key.PublicKey().Bytes(),
		SpiderX:     "/",
		SpiderY:     make([]int64, 10),
	}
	result, err := UClient(conn, config, context.Background(), xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(addr.Port)))
	if err == nil || result != nil {
		t.Fatalf("expected an unverified REALITY connection, got %v, %v", result, err)
	}
	select {
	case <-requestStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("camouflage HTTP request did not start")
	}
	// The camouflage request owns the connection after UClient returns an error.
	time.Sleep(9 * time.Second)
	if conn.closed.Load() {
		t.Fatal("camouflage connection was closed by failed setup cleanup")
	}
	release.Do(func() { close(releaseResponse) })
	select {
	case err := <-responseWritten:
		if err != nil {
			t.Fatalf("camouflage request failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("camouflage response did not complete")
	}
}

func TestUClientClosesSocketOnInvalidFingerprint(t *testing.T) {
	t.Parallel()
	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()
	conn := &closeTrackingConn{Conn: raw}
	result, err := UClient(conn, &Config{Fingerprint: "invalid"}, context.Background(), xnet.TCPDestination(xnet.LocalHostIP, 443))
	if err == nil || result != nil {
		t.Fatalf("expected fingerprint validation error, got %v, %v", result, err)
	}
	if !conn.closed.Load() {
		t.Fatal("fingerprint validation error left the socket open")
	}
}
