package dns_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/app/dispatcher"
	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	featuredns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

func TestTCPNameServerDispatchLinkAndLocal(t *testing.T) {
	for _, scheme := range []string{"tcp", "tcp+local"} {
		t.Run(scheme, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			local := listenTCPDNS(t)
			routed := listenTCPDNS(t)
			peer := routed
			if scheme == "tcp+local" {
				peer = local
			}
			target := net.DestinationFromAddr(routed.Addr())
			const dnsTag = "tcp-nameserver"
			const outboundTag = "tcp-dns-route"
			const serverTimeoutMS = 900
			instance, err := core.New(&core.Config{
				App: []*serial.TypedMessage{
					serial.ToTypedMessage(&appdns.Config{
						QueryStrategy: appdns.QueryStrategy_USE_IP4,
						NameServer: []*appdns.NameServer{{
							Tag:       dnsTag,
							TimeoutMs: serverTimeoutMS,
							Address:   &net.Endpoint{Address: net.NewIPOrDomain(net.DomainAddress(scheme + "://" + local.Addr().String()))},
						}},
					}),
					serial.ToTypedMessage(&dispatcher.Config{}),
					serial.ToTypedMessage(&proxyman.OutboundConfig{}),
					serial.ToTypedMessage(&policy.Config{}),
					serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{
						InboundTag: []string{dnsTag},
						TargetTag:  &router.RoutingRule_Tag{Tag: outboundTag},
					}}}),
				},
				Outbound: []*core.OutboundHandlerConfig{
					{ProxySettings: serial.ToTypedMessage(&freedom.Config{})},
					{Tag: outboundTag, ProxySettings: serial.ToTypedMessage(&freedom.Config{
						Firewall: []*freedom.FirewallConfig{{Action: freedom.RuleAction_Allow}},
						DestinationOverride: &freedom.DestinationOverride{Server: &protocol.ServerEndpoint{
							Address: net.NewIPOrDomain(target.Address),
							Port:    uint32(target.Port),
						}},
					})},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { instance.Close() })
			if err := instance.Start(); err != nil {
				t.Fatal(err)
			}
			client := instance.GetFeature(featuredns.ClientType()).(featuredns.ContextClient)
			type result struct {
				ips []net.IP
				err error
			}
			lookup := func(ctx context.Context, name string) <-chan result {
				done := make(chan result, 1)
				go func() {
					ips, _, err := client.LookupIPContext(ctx, name, featuredns.IPOption{IPv4Enable: true})
					done <- result{ips: ips, err: err}
				}()
				return done
			}
			check := func(ch <-chan result) result {
				t.Helper()
				select {
				case value := <-ch:
					return value
				case <-ctx.Done():
					t.Fatal("DNS lookup did not return")
					return result{}
				}
			}

			const sharedName = "shared-tcp.invalid"
			waiter, cancelWaiter := context.WithCancel(ctx)
			defer cancelWaiter()
			firstLookup := lookup(waiter, sharedName)
			conn, frame := acceptTCPDNSQuery(t, peer, sharedName)
			secondLookup := lookup(ctx, sharedName)
			cancelWaiter()
			if got := check(firstLookup); !errors.Is(got.err, context.Canceled) {
				t.Fatalf("canceled waiter: %v", got.err)
			}
			if err := buf.WriteAllBytes(conn, frame[:1], nil); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-secondLookup:
				t.Fatalf("lookup finished before full DNS frame: %v", got)
			case <-time.After(20 * time.Millisecond):
			}
			if err := buf.WriteAllBytes(conn, frame[1:], nil); err != nil {
				t.Fatal(err)
			}
			if got := check(secondLookup); got.err != nil || len(got.ips) != 1 || !got.ips[0].Equal(net.ParseIP("192.0.2.33")) {
				t.Fatalf("shared answer: %v", got)
			}
			requireTCPDNSClose(t, conn)

			const shortName = "short-tcp.invalid"
			short := lookup(ctx, shortName)
			conn, frame = acceptTCPDNSQuery(t, peer, shortName)
			// The wire packet is complete, but its TCP frame declares one more byte.
			// An incomplete frame must never be parsed and cached as a DNS answer.
			binary.BigEndian.PutUint16(frame[:2], uint16(len(frame)-1))
			if err := buf.WriteAllBytes(conn, frame, nil); err != nil {
				t.Fatal(err)
			}
			if err := conn.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if got := check(short); got.err == nil || len(got.ips) != 0 {
				t.Fatalf("incomplete DNS frame was accepted: %v", got)
			}
			requireTCPDNSClose(t, conn)

			const heldName = "held-tcp.invalid"
			held := lookup(ctx, heldName)
			conn, _ = acceptTCPDNSQuery(t, peer, heldName)
			if got := check(held); got.err == nil || len(got.ips) != 0 {
				t.Fatalf("unanswered DNS request: %v", got)
			}
			requireTCPDNSClose(t, conn)
		})
	}
}

func listenTCPDNS(t *testing.T) *net.TCPListener {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	return listener
}

func acceptTCPDNSQuery(t *testing.T, listener *net.TCPListener, name string) (*net.TCPConn, []byte) {
	t.Helper()
	if err := listener.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var prefix [2]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, binary.BigEndian.Uint16(prefix[:]))
	if _, err := io.ReadFull(conn, data); err != nil {
		t.Fatal(err)
	}
	query := new(dns.Msg)
	if err := query.Unpack(data); err != nil {
		t.Fatal(err)
	}
	if len(query.Question) != 1 || query.Question[0].Name != name+"." || query.Question[0].Qtype != dns.TypeA {
		t.Fatalf("received unexpected query: %v", query.Question)
	}
	answer := new(dns.Msg).SetReply(query)
	answer.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: name + ".", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
		A:   net.ParseIP("192.0.2.33"),
	}}
	data, err = answer.Pack()
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 2, len(data)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(data)))
	return conn, append(frame, data...)
}

func requireTCPDNSClose(t *testing.T, conn *net.TCPConn) {
	t.Helper()
	var data [1]byte
	if n, err := conn.Read(data[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("DNS connection did not close: read %d bytes, %v", n, err)
	}
}
