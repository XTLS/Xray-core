package freedom

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet"
)

type freedomPacketTestDNS struct {
	dns.Client
	waiting chan struct{}
}

func (*freedomPacketTestDNS) LookupIP(string, dns.IPOption) ([]net.IP, uint32, error) {
	return nil, 0, errors.New("unexpected contextless lookup")
}

func (d *freedomPacketTestDNS) LookupIPContext(ctx context.Context, domain string, _ dns.IPOption) ([]net.IP, uint32, error) {
	if domain == "localhost" {
		select {
		case d.waiting <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, 0, ctx.Err()
	}
	return []net.IP{net.LocalHostIP.IP()}, 60, nil
}

func TestFreedomPacketWriterCanceledLookupReleasesBatch(t *testing.T) {
	resolver := &freedomPacketTestDNS{waiting: make(chan struct{}, 1)}
	internet.InitSystemDialer(resolver, nil)
	t.Cleanup(func() { internet.InitSystemDialer(nil, nil) })

	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.LocalHostIP.IP()})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.LocalHostIP.IP()})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()

	conn := &net.PacketConnWrapper{PacketConn: socket, Dest: peer.LocalAddr()}
	dest := net.DestinationFromAddr(peer.LocalAddr())
	h := &Handler{resolveStrategy: internet.DomainStrategy_USE_IP46}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	writer := newPacketWriter(ctx, conn, h, nil, net.Destination{}, dest, nil)

	makePacket := func(domain, body string) *buf.Buffer {
		b := buf.New()
		b.WriteString(body)
		udp := net.UDPDestination(net.DomainAddress(domain), dest.Port)
		b.UDP = &udp
		return b
	}
	first := makePacket("localhost", "canceled first packet")
	remaining := makePacket("active.test", "canceled following packet")
	done := make(chan error, 1)
	go func() { done <- writer.WriteMultiBuffer(buf.MultiBuffer{first, remaining}) }()
	select {
	case <-resolver.waiting:
	case err := <-done:
		t.Fatalf("packet writer returned before the context-aware resolver waited: %v", err)
	case <-time.After(time.Second):
		t.Fatal("packet writer did not reach the context-aware resolver")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("packet writer returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("packet writer remained blocked after cancellation")
	}
	if !first.IsEmpty() || !remaining.IsEmpty() {
		t.Fatal("canceled packet writer retained buffers")
	}

	readBuffer := make([]byte, 64)
	if err := peer.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := peer.ReadFrom(readBuffer); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("canceled write reached the peer or failed with a socket error: %v", err)
	}

	live := newPacketWriter(t.Context(), conn, h, nil, net.Destination{}, dest, nil)
	if err := live.WriteMultiBuffer(buf.MultiBuffer{makePacket("active.test", "live packet")}); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err := peer.ReadFrom(readBuffer)
	if err != nil || string(readBuffer[:n]) != "live packet" {
		t.Fatalf("live packet received %q, %v", readBuffer[:n], err)
	}
}
