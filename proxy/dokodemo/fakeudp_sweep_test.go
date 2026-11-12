package dokodemo

import (
	gonet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

type mockConn struct {
	gonet.PacketConn
	closed bool
}

func (m *mockConn) Close() error { m.closed = true; return nil }

func TestSweepIdleClosesOnlyIdleFakeSockets(t *testing.T) {
	main := &mockConn{}
	idle := &mockConn{}
	busy := &mockConn{}
	dMain := net.UDPDestination(net.ParseAddress("1.1.1.1"), 1)
	dIdle := net.UDPDestination(net.ParseAddress("2.2.2.2"), 2)
	dBusy := net.UDPDestination(net.ParseAddress("3.3.3.3"), 3)
	now := time.Now()
	w := &PacketWriter{
		conn:  main,
		conns: map[net.Destination]net.PacketConn{dMain: main, dIdle: idle, dBusy: busy},
		used:  map[net.Destination]time.Time{dMain: now.Add(-time.Hour), dIdle: now.Add(-fakeUDPIdle - time.Second), dBusy: now.Add(-time.Second)},
	}
	w.sweepIdle(now)
	if main.closed || w.conns[dMain] == nil {
		t.Fatal("main fake socket must stay open")
	}
	if !idle.closed || w.conns[dIdle] != nil {
		t.Fatal("idle fake socket must be closed and removed")
	}
	if _, ok := w.used[dIdle]; ok {
		t.Fatal("idle entry must be removed from used")
	}
	if busy.closed || w.conns[dBusy] == nil {
		t.Fatal("recently used fake socket must stay open")
	}
	if !w.sweep.Equal(now) {
		t.Fatal("sweep time not updated")
	}
}
