package udp_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/udp"
)

type echoDispatcher struct {
	routing.Dispatcher
	calls atomic.Int32
}

type replySourceDispatcher struct {
	routing.Dispatcher
	source net.Destination
}

func (d *replySourceDispatcher) DispatchLink(_ context.Context, _ net.Destination, link *transport.Link) error {
	packet := func(source *net.Destination) *buf.Buffer {
		b := buf.New()
		b.WriteByte(1)
		b.UDP = source
		return b
	}
	return link.Writer.WriteMultiBuffer(buf.MultiBuffer{packet(&d.source), packet(nil)})
}

func (d *echoDispatcher) DispatchLink(ctx context.Context, destination net.Destination, link *transport.Link) error {
	d.calls.Add(1)
	for {
		data, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			return err
		}
		if err := link.Writer.WriteMultiBuffer(data); err != nil {
			return err
		}
	}
}

func TestSameDestinationDispatching(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	dispatcher := new(echoDispatcher)
	conn, err := udp.DialDispatcher(ctx, dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	dest := &net.UDPAddr{IP: []byte{127, 0, 0, 1}, Port: 53}
	for range 6 {
		if _, err := conn.WriteTo([]byte("abcd"), dest); err != nil {
			t.Fatal(err)
		}
	}
	for range 6 {
		var data [4]byte
		n, source, err := conn.ReadFrom(data[:])
		if err != nil || n != len(data) || string(data[:]) != "abcd" || source.String() != dest.String() {
			t.Fatalf("read %q from %v: %v", data[:n], source, err)
		}
	}
	if count := dispatcher.calls.Load(); count != 1 {
		t.Fatalf("route count = %d, want 1", count)
	}
}

func TestPacketConnRetainsLastReplySource(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	source := net.UDPDestination(net.LocalHostIP, 54)
	conn, err := udp.DialDispatcher(ctx, &replySourceDispatcher{source: source})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.WriteTo([]byte{1}, &net.UDPAddr{IP: []byte{127, 0, 0, 1}, Port: 53}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		var payload [1]byte
		n, from, err := conn.ReadFrom(payload[:])
		if err != nil || n != 1 || from == nil || from.String() != source.NetAddr() {
			t.Fatalf("read from %v (%d bytes), want %v: %v", from, n, source, err)
		}
	}
}
