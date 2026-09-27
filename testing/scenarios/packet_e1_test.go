package scenarios

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	gonet "net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/stats"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/exchange"
)

type packetPathGuard struct {
	outbound.Handler
	packet outbound.PacketHandler
	native atomic.Int32
	legacy atomic.Int32
}

type failFirstPacketGuard struct{ *packetPathGuard }

func (g *failFirstPacketGuard) PreparePacket(ctx context.Context) (exchange.PacketEndpoint, error) {
	leg, err := g.packetPathGuard.PreparePacket(ctx)
	if err == nil {
		leg.Writer = failedPacketWriter{}
	}
	return leg, err
}

type failedPacketWriter struct{}

func (failedPacketWriter) WritePacket([]byte, net.Destination) (int, error) {
	return 0, io.ErrClosedPipe
}

func (g *packetPathGuard) Dispatch(_ context.Context, link *transport.Link) {
	g.legacy.Add(1)
	common.Interrupt(link.Reader)
	common.Interrupt(link.Writer)
}
func (g *packetPathGuard) PreparePacket(ctx context.Context) (exchange.PacketEndpoint, error) {
	g.native.Add(1)
	return g.packet.PreparePacket(ctx)
}

func TestE1PacketNativeSocksFreedomAssociation(t *testing.T) {
	probe, err := gonet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*gonet.TCPAddr).Port
	probe.Close()
	config := fmt.Sprintf(`{"log":{"loglevel":"none"},"stats":{},"policy":{"system":{"statsOutboundUplink":true,"statsOutboundDownlink":true}},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"socks","settings":{"auth":"noauth","udp":true}}],"outbounds":[{"tag":"egress","protocol":"freedom","settings":{"finalRules":[{"action":"allow"}]}}]}`, port)
	server, err := core.StartInstance("json", []byte(config))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	manager := server.GetFeature(outbound.ManagerType()).(outbound.Manager)
	real := manager.GetHandler("egress")
	if real == nil {
		t.Fatal("missing outbound")
	}
	packet, ok := real.(outbound.PacketHandler)
	if !ok {
		t.Fatal("real outbound lacks packet admission")
	}
	guard := &packetPathGuard{Handler: real, packet: packet}
	if err := manager.RemoveHandler(context.Background(), "egress"); err != nil {
		t.Fatal(err)
	}
	if err := manager.AddHandler(context.Background(), guard); err != nil {
		t.Fatal(err)
	}
	tcp, err := gonet.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	tcp.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err = tcp.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err = io.ReadFull(tcp, method[:]); err != nil || method != [2]byte{5, 0} {
		t.Fatalf("method=%x err=%v", method, err)
	}
	if _, err = tcp.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	var response [10]byte
	if _, err = io.ReadFull(tcp, response[:]); err != nil || response[1] != 0 {
		t.Fatalf("associate=%x err=%v", response, err)
	}
	proxyAddr := &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1), Port: int(binary.BigEndian.Uint16(response[8:]))}
	client, err := gonet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var peers [2]gonet.PacketConn
	for i := range peers {
		peer, e := gonet.ListenPacket("udp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		peers[i] = peer
		defer peer.Close()
		go func(peer gonet.PacketConn, id byte) {
			buf := make([]byte, 65535)
			for {
				n, from, e := peer.ReadFrom(buf)
				if e != nil {
					return
				}
				reply := append([]byte{id}, buf[:n]...)
				peer.WriteTo(reply, from)
			}
		}(peer, byte('A'+i))
	}
	for i, payload := range [][]byte{{1, 2, 3}, {4, 5}, nil, {6}, bytes.Repeat([]byte{7}, 3000)} {
		index := i % 2
		targetPort := peers[index].LocalAddr().(*gonet.UDPAddr).Port
		wire := []byte{0, 0, 0, 1, 127, 0, 0, 1, byte(targetPort >> 8), byte(targetPort)}
		wire = append(wire, payload...)
		client.SetDeadline(time.Now().Add(time.Second))
		if _, err := client.WriteTo(wire, proxyAddr); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 65535)
		n, _, err := client.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		if n != 11+len(payload) || int(binary.BigEndian.Uint16(buf[8:10])) != targetPort || buf[10] != byte('A'+index) {
			t.Fatalf("reply[%d]=%x", i, buf[:n])
		}
		for j, b := range payload {
			if buf[11+j] != b {
				t.Fatalf("payload[%d][%d]", i, j)
			}
		}
	}
	tcp.Close()
	time.Sleep(50 * time.Millisecond)
	if guard.native.Load() != 1 || guard.legacy.Load() != 0 {
		t.Fatalf("packet native=%d legacy=%d", guard.native.Load(), guard.legacy.Load())
	}
	statsManager := server.GetFeature(stats.ManagerType()).(stats.Manager)
	up := statsManager.GetCounter("outbound>>>egress>>>traffic>>>uplink")
	down := statsManager.GetCounter("outbound>>>egress>>>traffic>>>downlink")
	if up == nil || down == nil || up.Value() <= 0 || down.Value() <= 0 {
		t.Fatalf("outbound packet counters up=%v down=%v", up, down)
	}
}

func TestE1PacketSocksReroutesAfterFailedLeg(t *testing.T) {
	peerA, err := gonet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peerA.Close()
	peerB, err := gonet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peerB.Close()
	portA := peerA.LocalAddr().(*gonet.UDPAddr).Port
	portB := peerB.LocalAddr().(*gonet.UDPAddr).Port
	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := peerB.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = peerB.WriteTo(buf[:n], from)
		}
	}()
	probe, err := gonet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*gonet.TCPAddr).Port
	probe.Close()
	config := fmt.Sprintf(`{"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"socks","settings":{"auth":"noauth","udp":true}}],"outbounds":[{"tag":"a","protocol":"freedom","settings":{"finalRules":[{"action":"allow"}]}},{"tag":"b","protocol":"freedom","settings":{"finalRules":[{"action":"allow"}]}}],"routing":{"rules":[{"type":"field","port":"%d","outboundTag":"a"},{"type":"field","port":"%d","outboundTag":"b"}]}}`, port, portA, portB)
	server, err := core.StartInstance("json", []byte(config))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	manager := server.GetFeature(outbound.ManagerType()).(outbound.Manager)
	realA, realB := manager.GetHandler("a"), manager.GetHandler("b")
	if realA == nil || realB == nil {
		t.Fatal("missing routed handlers")
	}
	guardA := &failFirstPacketGuard{&packetPathGuard{Handler: realA, packet: realA.(outbound.PacketHandler)}}
	guardB := &packetPathGuard{Handler: realB, packet: realB.(outbound.PacketHandler)}
	for _, tag := range []string{"a", "b"} {
		if err := manager.RemoveHandler(context.Background(), tag); err != nil {
			t.Fatal(err)
		}
	}
	for _, guard := range []outbound.Handler{guardA, guardB} {
		if err := manager.AddHandler(context.Background(), guard); err != nil {
			t.Fatal(err)
		}
	}
	tcp, err := gonet.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	_ = tcp.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := tcp.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(tcp, method[:]); err != nil || method != [2]byte{5, 0} {
		t.Fatalf("method=%x err=%v", method, err)
	}
	if _, err := tcp.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	var response [10]byte
	if _, err := io.ReadFull(tcp, response[:]); err != nil || response[1] != 0 {
		t.Fatalf("associate=%x err=%v", response, err)
	}
	proxyAddr := &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1), Port: int(binary.BigEndian.Uint16(response[8:]))}
	client, err := gonet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	send := func(port int, payload byte) {
		wire := []byte{0, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port), payload}
		if _, err := client.WriteTo(wire, proxyAddr); err != nil {
			t.Fatal(err)
		}
	}
	send(portA, 'a')
	deadline := time.Now().Add(time.Second)
	for guardA.native.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if guardA.native.Load() != 1 {
		t.Fatal("first route not prepared")
	}
	send(portB, 'b')
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	n, _, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 11 || buf[10] != 'b' || int(binary.BigEndian.Uint16(buf[8:10])) != portB {
		t.Fatalf("wrong replacement reply: %x", buf[:n])
	}
	if guardA.native.Load() != 1 || guardB.native.Load() != 1 || guardA.legacy.Load() != 0 || guardB.legacy.Load() != 0 {
		t.Fatalf("routes a=%d b=%d legacy a=%d b=%d", guardA.native.Load(), guardB.native.Load(), guardA.legacy.Load(), guardB.legacy.Load())
	}
	tcp.Close()
}
