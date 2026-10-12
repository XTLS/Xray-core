package xdns

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"golang.org/x/net/dns/dnsmessage"
)

type resolverOwnedPacketConn struct { net.PacketConn; once sync.Once; closed chan struct{} }
func (c *resolverOwnedPacketConn) Close() error { err := c.PacketConn.Close(); c.once.Do(func() { close(c.closed) }); return err }

func resolverBoundaryConfig() *Config {
	return &Config{Domains: []*DomainProto{{Name: "tunnel.test", LenLimit: 255, LabelLimit: 63, Types: []int32{16}, Edns0: 512}}, Resolvers: []*ResolverProto{{Type: "udp", Addr: "127.0.0.1:53"}}}
}

func TestClientConstructorFailureClosesEarlierResolvers(t *testing.T) {
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	owned := &resolverOwnedPacketConn{PacketConn: raw, closed: make(chan struct{})}
	defer owned.Close()
	config := resolverBoundaryConfig()
	config.Resolvers = append(config.Resolvers, &ResolverProto{Type: "unsupported"})
	dialer := &finalmask.Dialer{DialUDPContext: func(ctx context.Context, dest xnet.Destination) (net.Conn, error) { return &xnet.PacketConnWrapper{PacketConn: owned, Dest: &net.UDPAddr{IP: net.IPv4(127,0,0,1), Port: 53}}, nil }}
	if _, err := NewClient(config, dialer); err == nil { t.Fatal("constructor accepted unsupported resolver") }
	select { case <-owned.closed: case <-time.After(time.Second): t.Fatal("earlier resolver socket leaked") }
}

func TestFinalmaskXDNSOwnsDialAndPreservesContext(t *testing.T) {
	type outboundKey struct{}
	ctx := context.WithValue(context.Background(), outboundKey{}, "outbound")
	var dials atomic.Int32
	var owned *resolverOwnedPacketConn
	config := resolverBoundaryConfig()
	fm := finalmask.NewFinalMask(nil, []finalmask.UDPMask{config}, nil, nil, func(ctx context.Context, dest xnet.Destination) (net.PacketConn, net.Addr, error) {
		dials.Add(1)
		if ctx.Value(outboundKey{}) != "outbound" { return nil, nil, errors.New("outbound context was lost") }
		if dest.NetAddr() != "127.0.0.1:53" { return nil, nil, errors.New("opened the replaced outer connection") }
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil { return nil, nil, err }
		owned = &resolverOwnedPacketConn{PacketConn: conn, closed: make(chan struct{})}
		return owned, &net.UDPAddr{IP: net.IPv4(127,0,0,1), Port: 53}, nil
	}, nil)
	conn, err := fm.DialUDP(ctx, xnet.UDPDestination(xnet.IPAddress(net.IPv4(192,0,2,1)), 80))
	if err != nil { t.Fatal(err) }
	if dials.Load() != 1 { t.Fatalf("opened %d sockets, want only resolver socket", dials.Load()) }
	if err := conn.Close(); err != nil { t.Fatal(err) }
	select { case <-owned.closed: case <-time.After(time.Second): t.Fatal("finalmask did not release resolver socket") }
}

func TestResponseCapacityBoundaries(t *testing.T) {
	for _, qtype := range []uint16{1,5,16,28} {
		for _, budget := range []uint16{512,1232,4096} {
			domain, err := NewDomain("tunnel.test", 255, 63, []uint16{qtype}, budget)
			if err != nil { t.Fatal(err) }
			question := dnsmessage.Question{Name: dnsmessage.MustNewName("query.tunnel.test."), Type: dnsmessage.Type(qtype), Class: dnsmessage.ClassINET}
			response := NewResp(dnsmessage.Message{Questions: []dnsmessage.Question{question}}, domain, budget)
			if response.cap >= 4096 { t.Fatalf("qtype %d budget %d incorrectly promises 4096-byte downlink", qtype, budget) }
			data := make([]byte, response.cap)
			for i := range data { data[i] = byte(i*13) }
			wire := response.Encode(nil, data)
			if len(wire) > int(budget) { t.Fatalf("qtype %d wire length %d exceeds budget %d", qtype, len(wire), budget) }
			var msg dnsmessage.Message
			if err := msg.Unpack(wire); err != nil { t.Fatal(err) }
			buf := make([]byte, 4096)
			n := NewResp(msg, domain, budget).Decode(buf)
			if n != len(data) || !bytes.Equal(buf[:n], data) { t.Fatalf("qtype %d budget %d failed capacity round trip: %d/%d", qtype, budget, n, len(data)) }
		}
	}
}

func TestEmptyResponseDoesNotStartPollAndExtraPollCount(t *testing.T) {
	for extra := int32(0); extra <= 3; extra++ {
		t.Run(string(rune('0'+extra)), func(t *testing.T) {
			raw, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil { t.Fatal(err) }
			queries := make(chan struct{}, 32)
			answered := make(chan struct{}, 32)
			var payload atomic.Bool
			domain, err := NewDomain("tunnel.test", 255, 63, []uint16{16}, 512)
			if err != nil { t.Fatal(err) }
			done := make(chan struct{})
			go func() {
				defer close(done)
				buf := make([]byte, 512)
				for {
					n, addr, err := raw.ReadFrom(buf)
					if err != nil { return }
					queries <- struct{}{}
					var msg dnsmessage.Message
					if msg.Unpack(buf[:n]) != nil { return }
					var wire []byte
					if payload.CompareAndSwap(true, false) { wire = NewResp(msg, domain, 512).Encode(nil, []byte{0xc0, 3, 1, 2, 3}) } else { wire = resolverTestReply(buf[:n]) }
					if _, err := raw.WriteTo(wire, addr); err != nil { return }
					answered <- struct{}{}
				}
			}()
			t.Cleanup(func() { raw.Close(); <-done })
			config := resolverBoundaryConfig()
			config.Resolvers[0].Addr = raw.LocalAddr().String()
			config.ExtraPoll = extra
			dialer := &finalmask.Dialer{DialUDPContext: func(ctx context.Context, dest xnet.Destination) (net.Conn, error) { conn, err := net.ListenPacket("udp", "127.0.0.1:0"); if err != nil { return nil, err }; return &xnet.PacketConnWrapper{PacketConn: conn, Dest: raw.LocalAddr()}, nil }}
			client, err := NewClient(config, dialer)
			if err != nil { t.Fatal(err) }
			t.Cleanup(func() { client.Close() })
			consume := func(ch <-chan struct{}, count int) {
				for range count { select { case <-ch: case <-time.After(2*time.Second): t.Fatal("missing DNS request/response") } }
			}
			if _, err := client.WriteTo([]byte{1}, nil); err != nil { t.Fatal(err) }
			consume(queries, 1+int(extra))
			consume(answered, 1+int(extra))
			select { case <-queries: t.Fatal("empty response started automatic poll"); case <-time.After(initPollDelay+200*time.Millisecond): }
			payload.Store(true)
			if _, err := client.WriteTo([]byte{2}, nil); err != nil { t.Fatal(err) }
			consume(queries, 1+int(extra))
			received := make(chan error, 1)
			go func() { buf := make([]byte, 10); n, _, err := client.ReadFrom(buf); if err == nil && !bytes.Equal(buf[:n], []byte{1,2,3}) { err = errors.New("bad poll activation payload") }; received <- err }()
			select { case err := <-received: if err != nil { t.Fatal(err) }; case <-time.After(2*time.Second): t.Fatal("payload did not arrive") }
			consume(queries, 1+int(extra))
		})
	}
}
