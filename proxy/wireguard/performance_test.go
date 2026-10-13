package wireguard

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"golang.zx2c4.com/wireguard/conn"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

type bindTestCounter struct{ atomic.Int64 }

func (c *bindTestCounter) Value() int64      { return c.Load() }
func (c *bindTestCounter) Set(v int64) int64 { return c.Swap(v) }

func TestBindBatchReservedAndCounters(t *testing.T) {
	for _, family := range []struct{ network, address string }{{"udp4", "127.0.0.1:0"}, {"udp6", "[::1]:0"}} {
		t.Run(family.network, func(t *testing.T) {
			sender, _, _ := newThroughputBind(t, family.network, family.address)
			receiver, receive, udp := newThroughputBind(t, family.network, family.address)
			var sent, received bindTestCounter
			sender.writeCounter, receiver.readCounter = &sent, &received
			sender.reserved = []byte{3, 2, 1}
			writes, _, _ := benchmarkBuffers(conn.IdealBatchSize, 64)
			for i := range writes {
				writes[i][0], writes[i][4] = 4, byte(i)
			}
			ep := &conn.StdNetEndpoint{AddrPort: udp.LocalAddr().(*net.UDPAddr).AddrPort()}
			if err := sender.Send(writes, ep); err != nil {
				t.Fatal(err)
			}
			reads, sizes, eps := benchmarkBuffers(conn.IdealBatchSize, 64)
			count := 0
			for count < len(writes) {
				n, err := receive(reads[:len(writes)-count], sizes, eps)
				if err != nil {
					t.Fatal(err)
				}
				for i := range n {
					if sizes[i] != 64 || reads[i][4] != byte(count+i) || !bytes.Equal(reads[i][1:4], []byte{0, 0, 0}) {
						t.Fatalf("packet %d corrupted: %v", count+i, reads[i][:5])
					}
				}
				count += n
			}
			if sent.Value() != int64(len(writes)*64) || received.Value() != sent.Value() {
				t.Fatalf("counters sent=%d received=%d", sent.Value(), received.Value())
			}
			if sender.BatchSize() != conn.IdealBatchSize {
				t.Fatal("incorrect bind batch size")
			}
		})
	}
}

func TestBindCloseUnblocksReceive(t *testing.T) {
	b, receive, _ := newThroughputBind(t, "udp4", "127.0.0.1:0")
	bufs, sizes, eps := benchmarkBuffers(1, 64)
	done := make(chan error, 1)
	go func() { _, err := receive(bufs, sizes, eps); done <- err }()
	b.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("receive after close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not unblock receive")
	}
}

func TestNetTUNBatchReadViewsAndClose(t *testing.T) {
	dev := newThroughputTUN(t)
	payload := []byte("split packet views")
	for range conn.IdealBatchSize {
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: 32, Payload: buffer.MakeWithData(payload)})
		copy(pkt.NetworkHeader().Push(4), []byte{1, 2, 3, 4})
		var packets stack.PacketBufferList
		packets.PushBack(pkt)
		if n, err := dev.ep.WritePackets(packets); n != 1 || err != nil {
			t.Fatalf("queue packet: %d, %v", n, err)
		}
		pkt.DecRef()
	}
	bufs, sizes, _ := benchmarkBuffers(conn.IdealBatchSize, 64)
	n, err := dev.Read(bufs, sizes, 8)
	if err != nil || n != conn.IdealBatchSize {
		t.Fatalf("read batch: %d, %v", n, err)
	}
	want := append([]byte{1, 2, 3, 4}, payload...)
	for i := range n {
		if !bytes.Equal(bufs[i][8:8+sizes[i]], want) {
			t.Fatalf("packet %d: %v", i, bufs[i][8:8+sizes[i]])
		}
	}
	done := make(chan error, 1)
	go func() { _, err := dev.Read(bufs, sizes, 0); done <- err }()
	dev.Close()
	dev.Close()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("read after close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not unblock TUN reader")
	}
}

func TestNetTUNWriteDoesNotWaitForReader(t *testing.T) {
	dev := newThroughputTUN(t)
	writes := make([][]byte, conn.IdealBatchSize)
	for i := range writes {
		writes[i] = throughputEchoPacket()
	}
	done := make(chan error, 1)
	go func() { _, err := dev.Write(writes, 0); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("TUN write waited for reader")
	}
	bufs, sizes, _ := benchmarkBuffers(conn.IdealBatchSize, 2048)
	if n, err := dev.Read(bufs, sizes, 0); n != conn.IdealBatchSize || err != nil {
		t.Fatalf("read echo batch: %d, %v", n, err)
	}
}

func TestNetTUNTCPOptions(t *testing.T) {
	dev := newThroughputTUN(t)
	var send tcpip.TCPSendBufferSizeRangeOption
	var receive tcpip.TCPReceiveBufferSizeRangeOption
	var moderate tcpip.TCPModerateReceiveBufferOption
	var congestion tcpip.CongestionControlOption
	for _, option := range []tcpip.GettableTransportProtocolOption{&send, &receive, &moderate, &congestion} {
		if err := dev.stack.TransportProtocolOption(tcp.ProtocolNumber, option); err != nil {
			t.Fatal(err)
		}
	}
	if send.Default != 4<<20 || receive.Default != 4<<20 || send.Max != 16<<20 || receive.Max != 16<<20 || !moderate {
		t.Fatalf("unexpected TCP options: %v, %v, %v", send, receive, moderate)
	}
	if congestion != "cubic" {
		t.Fatalf("congestion control: %s", congestion)
	}
}

func TestUDPFlowKeyFamiliesAndPorts(t *testing.T) {
	v4 := xnet.UDPDestination(xnet.ParseAddress("10.0.0.1"), 123)
	v6 := xnet.UDPDestination(xnet.ParseAddress("::a00:1"), 123)
	otherPort := v4
	otherPort.Port++
	if flowKey(v4) == flowKey(v6) || flowKey(v4) == flowKey(otherPort) {
		t.Fatal("flow key collapsed addresses or ports")
	}
	keys := map[udpFlowKey]bool{flowKey(v4): true}
	var found bool
	if got := testing.AllocsPerRun(100, func() { found = keys[flowKey(v4)] }); got != 0 || !found {
		t.Fatalf("flow key lookup: allocations=%v found=%v", got, found)
	}
}

func TestRawUDPPacket(t *testing.T) {
	for _, addresses := range [][2]string{{"1.1.1.1", "10.66.0.2"}, {"fd00::1", "fd00::2"}} {
		t.Run(addresses[0], func(t *testing.T) {
			dev := newThroughputTUN(t)
			m := udpManager{stack: dev.stack}
			src := xnet.UDPDestination(xnet.ParseAddress(addresses[0]), 53)
			dst := xnet.UDPDestination(xnet.ParseAddress(addresses[1]), 1234)
			payload := []byte("UDP payload")
			if err := m.writeRawUDPPacket(payload, src, dst); err != nil {
				t.Fatal(err)
			}
			bufs, sizes, _ := benchmarkBuffers(1, 128)
			if _, err := dev.Read(bufs, sizes, 0); err != nil {
				t.Fatal(err)
			}
			packet := bufs[0][:sizes[0]]
			hdrSize := header.IPv4MinimumSize
			if !dst.Address.Family().IsIPv4() {
				hdrSize = header.IPv6MinimumSize
			}
			udp := header.UDP(packet[hdrSize:])
			if udp.SourcePort() != 53 || udp.DestinationPort() != 1234 || !bytes.Equal(packet[hdrSize+header.UDPMinimumSize:], payload) {
				t.Fatalf("bad UDP packet: %v", packet)
			}
		})
	}
}

func TestNetTUNReadAllocations(t *testing.T) {
	dev := newThroughputTUN(t)
	m := udpManager{stack: dev.stack}
	src := xnet.UDPDestination(xnet.ParseAddress("1.1.1.1"), 53)
	dst := xnet.UDPDestination(xnet.ParseAddress("10.66.0.2"), 1234)
	for range 101 {
		if err := m.writeRawUDPPacket([]byte("payload"), src, dst); err != nil {
			t.Fatal(err)
		}
	}
	bufs, sizes, _ := benchmarkBuffers(1, 128)
	var readErr error
	if got := testing.AllocsPerRun(100, func() { _, readErr = dev.Read(bufs, sizes, 0) }); got != 0 || readErr != nil {
		t.Fatalf("read: allocations=%v err=%v", got, readErr)
	}
}

// Hiding UDPConn exercises masked/custom PacketConn transports.
func TestBindPacketConnFallback(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	b := &bind{listenFunc: func() (net.PacketConn, error) {
		return struct{ net.PacketConn }{udp}, nil
	}}
	fns, _, err := b.Open(0)
	if err != nil {
		udp.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	data := []byte{4, 0, 0, 0, 9}
	if err := b.Send([][]byte{data}, &conn.StdNetEndpoint{AddrPort: udp.LocalAddr().(*net.UDPAddr).AddrPort()}); err != nil {
		t.Fatal(err)
	}
	bufs, sizes, eps := benchmarkBuffers(1, 32)
	if n, err := fns[0](bufs, sizes, eps); n != 1 || err != nil || !bytes.Equal(bufs[0][:sizes[0]], data) {
		t.Fatalf("fallback receive: n=%d err=%v packet=%v", n, err, bufs[0][:sizes[0]])
	}
}

func TestWireGuardTCPThroughput(t *testing.T) {
	client, server := newWireGuardTCPPair(t)
	payload := bytes.Repeat([]byte("WireGuard throughput"), 8192)
	got := make([]byte, len(payload))
	done := make(chan error, 1)
	go func() { _, err := io.ReadFull(server, got); done <- err }()
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("TCP payload corrupted through WireGuard")
	}
}
