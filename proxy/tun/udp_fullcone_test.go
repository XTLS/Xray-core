package tun

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// BenchmarkUDPNewSession measures what one new UDP flow costs the
// inbound while it stays open: QUIC and DNS open many short flows, and each
// one lives until the connection idle timeout.
func BenchmarkUDPNewSession(b *testing.B) {
	u := newUdpConnectionHandler(func(conn net.Conn, dest net.Destination) {}, nil)
	dst := net.UDPDestination(net.ParseAddress("1.1.1.1"), 443)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src := net.UDPDestination(net.IPAddress([]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), net.Port(1024+i%60000))
		u.HandlePacket(src, dst, &buf.Buffer{})
	}
}

func TestPacketQueueOrderAndClose(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	for i := 0; i < 3; i++ {
		b := buf.New()
		b.WriteByte(byte(i))
		if !q.push(b) {
			t.Fatalf("push %d rejected", i)
		}
	}
	for i := 0; i < 3; i++ {
		b, ok := q.pop()
		if !ok || b.Byte(0) != byte(i) {
			t.Fatalf("pop %d: got %v, %v", i, b, ok)
		}
		b.Release()
	}
	q.close()
	if _, ok := q.pop(); ok {
		t.Fatal("pop after close returned a packet")
	}
	if q.push(&buf.Buffer{}) {
		t.Fatal("push after close accepted")
	}
}

func TestPacketQueueLimit(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	for i := 0; i < udpQueueLimit; i++ {
		if !q.push(&buf.Buffer{}) {
			t.Fatalf("push %d rejected below the limit", i)
		}
	}
	if q.push(&buf.Buffer{}) {
		t.Fatal("push above the limit accepted")
	}
}

func TestPacketQueueCloseUnblocksReader(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	done := make(chan bool)
	go func() {
		_, ok := q.pop()
		done <- ok
	}()
	q.close()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("blocked pop returned a packet after close")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not wake the reader")
	}
}

func TestPacketQueueDropsDrainedStorage(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	for i := 0; i < 100; i++ {
		q.push(&buf.Buffer{})
	}
	for i := 0; i < 100; i++ {
		q.pop()
	}
	if q.items != nil {
		t.Fatalf("drained queue still holds %d slots", cap(q.items))
	}
}

// A closing stack must end its UDP flows: the dispatch reading a flow gets EOF and returns, instead of
// waiting on the queue forever and keeping its outbound alive past the instance; a packet that arrives
// afterwards opens no flow.
func TestUDPHandlerCloseAllEndsFlows(t *testing.T) {
	done := make(chan struct{}, 2)
	handler := newUdpConnectionHandler(func(conn net.Conn, dest net.Destination) {
		b := make([]byte, 2048)
		for {
			if _, err := conn.Read(b); err != nil {
				done <- struct{}{}
				return
			}
		}
	}, func(data []byte, src net.Destination, dst net.Destination) error { return nil })
	dst := net.UDPDestination(net.IPAddress([]byte{10, 6, 0, 2}), 53)
	for _, port := range []net.Port{40000, 40001} {
		src := net.UDPDestination(net.IPAddress([]byte{10, 255, 0, 2}), port)
		handler.HandlePacket(src, dst, buf.FromBytes([]byte("query")))
	}
	handler.closeAll()
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("flow %d still running after closeAll", i)
		}
	}
	handler.HandlePacket(net.UDPDestination(net.IPAddress([]byte{10, 255, 0, 2}), 40002), dst, buf.FromBytes([]byte("late")))
	handler.RLock()
	n := len(handler.udpConns)
	handler.RUnlock()
	if n != 0 {
		t.Fatalf("%d flows in the table after closeAll", n)
	}
}
