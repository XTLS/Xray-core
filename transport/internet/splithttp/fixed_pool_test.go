package splithttp

import (
	"context"
	"fmt"
	"io"
	stdnet "net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

type poolTestConn struct{ closed atomic.Bool }

func (c *poolTestConn) IsClosed() bool { return c.closed.Load() }
func (c *poolTestConn) Close() error {
	c.closed.Store(true)
	return nil
}

func TestFixedPoolSerialRotation(t *testing.T) {
	var created atomic.Int32
	m := NewXmuxManager(XmuxConfig{MaxConnections: &RangeConfig{From: 4, To: 4}}, func() XmuxConn {
		created.Add(1)
		return &poolTestConn{}
	})

	clients := make([]*XmuxClient, 4)
	for i := range clients {
		clients[i] = m.GetXmuxClient(context.Background())
		clients[i].AddRunning()
	}
	if created.Load() != 4 {
		t.Fatalf("created=%d, want 4", created.Load())
	}
	for _, c := range clients {
		c.UnreusableAt = time.Now().Add(-time.Second)
	}

	replacement := m.GetXmuxClient(context.Background())
	replacement.AddRunning()
	if created.Load() != 5 {
		t.Fatalf("first rotation created=%d, want 5 total", created.Load())
	}
	if len(m.xmuxClients) != 4 {
		t.Fatalf("active pool=%d, want 4", len(m.xmuxClients))
	}
	if m.draining == nil {
		t.Fatal("expected one draining carrier")
	}
	firstDraining := m.draining

	for range 100 {
		m.GetXmuxClient(context.Background())
	}
	if created.Load() != 5 {
		t.Fatalf("parallel rotation started while one carrier drains: created=%d", created.Load())
	}
	if m.draining != firstDraining {
		t.Fatal("draining carrier changed before it finished")
	}

	firstDraining.DoneRunning()
	if !firstDraining.XmuxConn.IsClosed() {
		t.Fatal("drained carrier was not closed")
	}
	secondReplacement := m.GetXmuxClient(context.Background())
	secondReplacement.AddRunning()
	if created.Load() != 6 {
		t.Fatalf("second rotation created=%d, want 6 total", created.Load())
	}
	if len(m.xmuxClients) != 4 || m.draining == nil {
		t.Fatalf("second rotation state: active=%d draining=%v", len(m.xmuxClients), m.draining != nil)
	}
}

func TestFixedH2RoundTripperUsesOnePhysicalConnection(t *testing.T) {
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var accepts atomic.Int32
	server := &http2.Server{MaxConcurrentStreams: 32}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			go server.ServeConn(conn, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(10 * time.Millisecond)
				fmt.Fprint(w, "ok")
			})})
		}
	}()

	rt := &fixedH2RoundTripper{
		transport: &http2.Transport{AllowHTTP: true, StrictMaxConcurrentStreams: true},
		dial: func(context.Context) (stdnet.Conn, error) {
			return stdnet.Dial("tcp", ln.Addr().String())
		},
	}
	defer rt.Close()

	var wg sync.WaitGroup
	errCh := make(chan error, 256)
	for range 256 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", "http://xhttp.test/", nil)
			resp, err := rt.RoundTrip(req)
			if err != nil {
				errCh <- err
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	if got := accepts.Load(); got != 1 {
		t.Fatalf("physical H2 connections=%d, want 1", got)
	}
}
