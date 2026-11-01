package inbound

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

func newUDPBufferWorker(size int32) *udpWorker {
	return &udpWorker{
		ctx:        policy.ContextWithBufferPolicy(context.Background(), policy.Buffer{PerConnection: size}),
		address:    net.LocalHostIP,
		activeConn: make(map[connID]*udpConn),
	}
}

func TestUDPConnectionBufferPolicy(t *testing.T) {
	const packetSize = 1400
	for _, tc := range []struct {
		name   string
		policy int32
		limit  int32
	}{
		{"configured", 256 * 1024, 256 * 1024},
		{"small", 4 * 1024, 16 * 1024},
		{"zero", 0, 16 * 1024},
		{"unlimited", -1, 1024 * 1024},
		{"large", 8 * 1024 * 1024, 1024 * 1024},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newUDPBufferWorker(tc.policy)
			id := connID{src: net.UDPDestination(net.LocalHostIP, 12345)}
			conn, _ := w.getConnection(id)
			defer conn.Close()
			for i := 0; i < 1000; i++ {
				b := buf.New()
				binary.BigEndian.PutUint32(b.Extend(packetSize), uint32(i))
				dest := net.UDPDestination(net.LocalHostIP, 23456)
				b.UDP = &dest
				if err := conn.writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
					t.Fatal(err)
				}
			}
			mb, err := conn.reader.ReadMultiBuffer()
			if err != nil {
				t.Fatal(err)
			}
			defer buf.ReleaseMulti(mb)
			// Pipe admits one packet beyond the limit before dropping writes.
			wantPackets := int(tc.limit)/packetSize + 1
			if len(mb) != wantPackets {
				t.Fatalf("retained %d packets, want %d for policy %d", len(mb), wantPackets, tc.policy)
			}
			for i, b := range mb {
				if b.Len() != packetSize || binary.BigEndian.Uint32(b.BytesTo(4)) != uint32(i) || b.UDP == nil || b.UDP.Port != 23456 {
					t.Fatalf("packet %d changed", i)
				}
			}
		})
	}
}

func TestUDPOverflowDoesNotBlockOtherSessions(t *testing.T) {
	w := newUDPBufferWorker(64 * 1024)
	id := connID{src: net.UDPDestination(net.LocalHostIP, 12345)}
	first, _ := w.getConnection(id)
	defer first.Close()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for i := 0; i < 100; i++ {
			b := buf.New()
			b.Extend(buf.Size)
			first.writer.WriteMultiBuffer(buf.MultiBuffer{b})
		}
	}()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("a full UDP session blocked packet dispatch")
	}
	second, _ := w.getConnection(connID{src: net.UDPDestination(net.LocalHostIP, 12346)})
	defer second.Close()
	b := buf.New()
	b.Write([]byte("second session"))
	if err := second.writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatal(err)
	}
	mb, err := second.reader.(*pipe.Reader).ReadMultiBufferTimeout(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(mb)
	if string(mb[0].Bytes()) != "second session" {
		t.Fatal("second session packet changed")
	}
	mb, err = first.reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	buf.ReleaseMulti(mb)
}

func TestUDPSmallPacketsHaveFiniteBufferCount(t *testing.T) {
	w := newUDPBufferWorker(-1)
	conn, _ := w.getConnection(connID{src: net.UDPDestination(net.LocalHostIP, 12345)})
	defer conn.Close()
	for i := 0; i < 2000; i++ {
		b := buf.New()
		binary.BigEndian.PutUint32(b.Extend(64), uint32(i))
		if err := conn.writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			t.Fatal(err)
		}
	}
	mb, err := conn.reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(mb)
	if len(mb) != 1024 {
		t.Fatalf("retained %d small packets, want 1024", len(mb))
	}
	for i, b := range mb {
		if b.Len() != 64 || binary.BigEndian.Uint32(b.BytesTo(4)) != uint32(i) {
			t.Fatalf("packet %d changed", i)
		}
	}
}

type udpBufferTestProxy struct {
	handled chan struct{}
}

func (*udpBufferTestProxy) Network() []net.Network { return []net.Network{net.Network_UDP} }

func (p *udpBufferTestProxy) Process(context.Context, net.Network, stat.Connection, routing.Dispatcher) error {
	select {
	case p.handled <- struct{}{}:
	default:
	}
	return nil
}

func TestUDPWorkerRetainsBurstWhileDispatchIsPaused(t *testing.T) {
	p := &udpBufferTestProxy{handled: make(chan struct{}, 1)}
	w := newUDPBufferWorker(1024 * 1024)
	w.ctx = context.WithValue(w.ctx, "cone", true)
	w.proxy = p
	w.stream = &internet.MemoryStreamConfig{}
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	// Pause callback's connection lookup, leaving the socket reader active.
	w.Lock()
	defer func() {
		w.hub.Close()
		for packet := range w.hub.Receive() {
			packet.Payload.Release()
		}
		w.Unlock()
		select {
		case <-p.handled:
		case <-time.After(3 * time.Second):
			t.Error("packet dispatch did not resume")
		}
		w.Close()
	}()
	sender, err := net.DialUDP("udp", nil, w.hub.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	for i := 0; i < 600; i++ {
		if _, err := sender.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		// Wait for the socket reader, avoiding kernel-buffer or scheduling loss.
		// The dispatcher may have taken one packet before blocking on w.Lock.
		deadline := time.Now().Add(2 * time.Second)
		for len(w.hub.Receive()) < i {
			if time.Now().After(deadline) {
				t.Fatalf("receive queue retained only %d of %d packets", len(w.hub.Receive()), i+1)
			}
			time.Sleep(time.Millisecond)
		}
	}
}
