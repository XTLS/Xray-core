package outbound

import (
	"context"
	gonet "net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type testDialer struct {
	up    atomic.Bool
	dials atomic.Int32
}

func (d *testDialer) Dial(context.Context, net.Destination) (stat.Connection, error) {
	d.dials.Add(1)
	if d.up.Load() {
		conn, _ := gonet.Pipe()
		return conn, nil
	}
	return nil, errors.New("connection refused")
}

func (d *testDialer) DestIpAddress() net.IP { return nil }

func (d *testDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

func newTestpreHandler() *Handler {
	h := &Handler{testpre: 1, preConns: make(chan *ConnExpire), preWake: make(chan struct{}, 1)}
	h.preCtx, h.preCancel = context.WithCancel(context.Background())
	return h
}

func TestPreConnectBacksOffAndStopsOnClose(t *testing.T) {
	h := newTestpreHandler()
	d := &testDialer{}
	stopped := make(chan struct{})
	go func() {
		h.preConnect(d, net.TCPDestination(net.LocalHostIP, 1))
		close(stopped)
	}()

	// Waits of 200 ms, 400 ms, 800 ms... between failed attempts: 3 dials in the first second.
	time.Sleep(time.Second)
	if n := d.dials.Load(); n > 4 {
		t.Error("expected pre-connect to back off after failures, but it dialed", n, "times in a second")
	}

	h.Close()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Error("expected pre-connect to stop after Close")
	}
}

func TestGetPreConnWakesBackedOffPreConnect(t *testing.T) {
	h := newTestpreHandler()
	defer h.Close()
	d := &testDialer{}
	go h.preConnect(d, net.TCPDestination(net.LocalHostIP, 1))

	// After failing for 1.5 s, the next attempt would be about 1.5 s away.
	time.Sleep(time.Millisecond * 1500)
	d.up.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	start := time.Now()
	conn, err := h.getPreConn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if elapsed := time.Since(start); elapsed > time.Millisecond*500 {
		t.Error("expected a waiting request to wake the pre-connect, but it waited", elapsed)
	}
}

func TestGetPreConnFallsBackWhenNoneComes(t *testing.T) {
	h := newTestpreHandler()
	defer h.Close()
	conn, err := h.getPreConn(context.Background())
	if conn != nil || err != nil {
		t.Error("expected neither a connection nor an error, so that the request dials directly, but got", conn, err)
	}
}

func TestGetPreConnReturnsOnCancelAndClose(t *testing.T) {
	h := newTestpreHandler()

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
	defer cancel()
	if _, err := h.getPreConn(ctx); err == nil {
		t.Error("expected an error once the request is canceled")
	}

	h.Close()
	if _, err := h.getPreConn(context.Background()); err == nil {
		t.Error("expected an error once the handler is closed")
	}
}
