package dns_test

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/app/dispatcher"
	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	featureDNS "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/proxy/freedom"
)

func TestUDPNameServerDispatchLinkAndLocal(t *testing.T) {
	for _, scheme := range []string{"udp", "udp+local"} {
		t.Run(scheme, func(t *testing.T) {
			listen := func() *net.UDPConn {
				t.Helper()
				conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { conn.Close() })
				if err := conn.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
					t.Fatal(err)
				}
				return conn
			}
			local, routed := listen(), listen()
			target := net.DestinationFromAddr(routed.LocalAddr())
			const dnsTag = "udp-nameserver"
			const outboundTag = "udp-dns-route"
			config := &core.Config{
				App: []*serial.TypedMessage{
					serial.ToTypedMessage(&appdns.Config{QueryStrategy: appdns.QueryStrategy_USE_IP4, NameServer: []*appdns.NameServer{{
						Tag: dnsTag, TimeoutMs: 2800, Address: &net.Endpoint{Address: net.NewIPOrDomain(net.DomainAddress(scheme + "://" + local.LocalAddr().String()))},
					}}}),
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
							Address: net.NewIPOrDomain(target.Address), Port: uint32(target.Port),
						}},
					})},
				},
			}
			instance, err := core.New(config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { instance.Close() })
			if err := instance.Start(); err != nil {
				t.Fatal(err)
			}

			peer := routed
			if scheme == "udp+local" {
				peer = local
			}
			const answerIP = "192.0.2.17"
			type result struct {
				ips []net.IP
				err error
			}
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			client := instance.GetFeature(featureDNS.ClientType()).(featureDNS.ContextClient)
			lookup := func(domain string) <-chan result {
				done := make(chan result, 1)
				go func() {
					ips, _, err := client.LookupIPContext(ctx, domain, featureDNS.IPOption{IPv4Enable: true})
					done <- result{ips, err}
				}()
				return done
			}
			var wire [2048]byte
			var source string
			receive := func(name string) (dns.Msg, *net.UDPAddr) {
				t.Helper()
				n, addr, err := peer.ReadFromUDP(wire[:])
				if err != nil {
					t.Fatal(err)
				}
				if source == "" {
					source = addr.String()
				}
				if source != addr.String() {
					t.Fatalf("query reopened its transport: got %s, want %s", addr, source)
				}
				var msg dns.Msg
				if err := msg.Unpack(wire[:n]); err != nil {
					t.Fatal(err)
				}
				if len(msg.Question) != 1 || msg.Question[0].Name != name+"." || msg.Question[0].Qtype != dns.TypeA {
					t.Fatalf("unexpected question: %v", msg.Question)
				}
				return msg, addr
			}
			reply := func(query *dns.Msg, addr *net.UDPAddr, truncated bool) {
				t.Helper()
				msg := new(dns.Msg).SetReply(query)
				msg.Truncated = truncated
				if !truncated {
					msg.Answer = []dns.RR{&dns.A{
						Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.ParseIP(answerIP),
					}}
				}
				packet, err := msg.Pack()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := peer.WriteToUDP(packet, addr); err != nil {
					t.Fatal(err)
				}
			}
			check := func(done <-chan result) {
				t.Helper()
				select {
				case got := <-done:
					if got.err != nil || len(got.ips) != 1 || got.ips[0].String() != answerIP {
						t.Fatalf("lookup returned %v, %v", got.ips, got.err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}

			done := lookup("truncate.example")
			first, addr := receive("truncate.example")
			if first.IsEdns0() != nil {
				t.Fatal("initial query unexpectedly used EDNS")
			}
			reply(&first, addr, true)
			retry, addr := receive("truncate.example")
			if opt := retry.IsEdns0(); opt == nil || opt.UDPSize() != 1350 || retry.Id == first.Id {
				t.Fatalf("retry ID %d, first ID %d, retry EDNS %v", retry.Id, first.Id, opt)
			}
			reply(&retry, addr, false)
			check(done)

			done = lookup("next.example")
			next, addr := receive("next.example")
			reply(&next, addr, false)
			check(done)
		})
	}
}
