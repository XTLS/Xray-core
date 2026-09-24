package tun

import (
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
)

// chanClosed reports whether ch is closed, draining any buffered packets first
// so a buffered-but-open channel is not mistaken for a closed one.
func chanClosed(ch chan *packet) bool {
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return true
			}
		default:
			return false
		}
	}
}

// A UDP flow's connection is Closed twice on teardown (the outbound handler
// interrupts the link, then HandleConnection's deferred Close fires). If a new
// packet from the same src:port arrives between those two closes, a fresh
// udpConn occupies the map slot. The stale second Close must not evict or close
// that newer connection.
func TestConnectionFinishedOnlyClosesFinishingConn(t *testing.T) {
	handler := newUdpConnectionHandler(
		func(conn xnet.Conn, dest xnet.Destination) {}, // no-op: don't auto-close
		func(data []byte, src xnet.Destination, dst xnet.Destination) error { return nil },
	)
	src := xnet.UDPDestination(xnet.LocalHostIP, 12345)
	dst := xnet.UDPDestination(xnet.LocalHostIP, 53)

	handler.HandlePacket(src, dst, []byte("a"))
	old := handler.udpConns[src]
	if old == nil {
		t.Fatal("expected a connection for the first packet")
	}

	// First flow finishes and is correctly removed from the map.
	old.Close()
	if _, found := handler.udpConns[src]; found {
		t.Fatal("finishing the first conn should remove it from the map")
	}

	// A new packet from the same src:port creates a fresh connection.
	handler.HandlePacket(src, dst, []byte("b"))
	fresh := handler.udpConns[src]
	if fresh == nil || fresh == old {
		t.Fatal("expected a new connection to occupy the reused slot")
	}

	// The old flow's deferred (stale) second Close fires late.
	old.Close()

	if got := handler.udpConns[src]; got != fresh {
		t.Fatalf("stale close evicted the newer conn: got %v, want %v", got, fresh)
	}
	if chanClosed(fresh.egress) {
		t.Fatal("stale close closed the newer conn's egress channel")
	}
}
