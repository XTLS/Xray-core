package http

import (
	"context"
	gotls "crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type h2TestDialer struct {
	addr string
}

func (d *h2TestDialer) Dial(ctx context.Context, dest net.Destination) (stat.Connection, error) {
	conn, err := net.Dial("tcp", d.addr)
	if err != nil {
		return nil, err
	}
	return tls.Client(conn, &gotls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}), nil
}

func (d *h2TestDialer) DestIpAddress() net.IP {
	return nil
}

func (d *h2TestDialer) SetOutboundGateway(ctx context.Context, ob *session.Outbound) {}

func TestHTTP2RefusedConnectKeepsSharedConnection(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Host {
		case "allowed.test:443":
		case "reset.test:443":
			panic(http.ErrAbortHandler) // RST_STREAM without a response
		default:
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		b := make([]byte, 1024)
		for {
			n, err := r.Body.Read(b)
			if n > 0 {
				w.Write(b[:n])
				w.(http.Flusher).Flush()
			}
			if err != nil {
				return
			}
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	cachedH2Mutex.Lock()
	saved := cachedH2Conns
	cachedH2Conns = nil
	cachedH2Mutex.Unlock()
	defer func() {
		cachedH2Mutex.Lock()
		cachedH2Conns = saved
		cachedH2Mutex.Unlock()
	}()

	ctx := context.Background()
	dialer := &h2TestDialer{addr: server.Listener.Addr().String()}
	dest := net.TCPDestination(net.LocalHostIP, net.Port(443))

	conn, err := setUpHTTPTunnel(ctx, dest, "allowed.test:443", nil, dialer, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	echo := func(msg string) error {
		if _, err := conn.Write([]byte(msg)); err != nil {
			return err
		}
		errCh := make(chan error, 1)
		go func() {
			b := make([]byte, len(msg))
			_, err := io.ReadFull(conn, b)
			if err == nil && string(b) != msg {
				err = io.ErrUnexpectedEOF
			}
			errCh <- err
		}()
		select {
		case err := <-errCh:
			return err
		case <-time.After(5 * time.Second):
			return context.DeadlineExceeded
		}
	}
	if err := echo("first"); err != nil {
		t.Fatalf("tunnel does not work: %v", err)
	}

	for _, target := range []string{"denied.test:443", "reset.test:443"} {
		if _, err := setUpHTTPTunnel(ctx, dest, target, nil, dialer, nil, nil); err == nil {
			t.Fatalf("%s: expected an error for a refused CONNECT", target)
		}
		if err := echo(target); err != nil {
			t.Fatalf("%s: refused CONNECT broke the other tunnel on the same HTTP/2 connection: %v", target, err)
		}
	}
}
