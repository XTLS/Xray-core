package dns_test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	featureDNS "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	routingSession "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask/xdns"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

type dnsRouteDispatch struct {
	ctx  context.Context
	dest xnet.Destination
	tag  string
}

// This dispatcher uses the real router and a real UDP socket behind the normal UDP dispatcher.
type dnsRouteDispatcher struct {
	t      *testing.T
	router *router.Router
	seen   chan dnsRouteDispatch
}

func (*dnsRouteDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*dnsRouteDispatcher) Start() error      { return nil }
func (*dnsRouteDispatcher) Close() error      { return nil }
func (*dnsRouteDispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	return errors.New("unused DispatchLink")
}

func (d *dnsRouteDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: dest}})
	route, err := d.router.PickRoute(routingSession.AsRoutingContext(ctx))
	if err != nil {
		return nil, err
	}
	d.seen <- dnsRouteDispatch{ctx: ctx, dest: dest, tag: route.GetOutboundTag()}
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: dest.Address.IP(), Port: int(dest.Port)})
	if err != nil {
		return nil, err
	}
	d.t.Cleanup(func() { _ = conn.Close() })
	context.AfterFunc(ctx, func() { _ = conn.Close() })
	return &transport.Link{Reader: buf.NewPacketReader(conn), Writer: buf.NewWriter(conn)}, nil
}

func dnsUDPContextFixture(t *testing.T, mode string, answer bool) (*appdns.DNS, *core.Instance, <-chan dnsRouteDispatch, <-chan struct{}) {
	t.Helper()
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	received := make(chan struct{}, 8)
	go func() {
		packet := make([]byte, 4096)
		for {
			n, peer, err := upstream.ReadFrom(packet)
			if err != nil {
				return
			}
			query := new(mdns.Msg)
			if err := query.Unpack(packet[:n]); err != nil {
				t.Error(err)
				return
			}
			received <- struct{}{}
			if !answer {
				continue
			}
			response := new(mdns.Msg)
			response.SetReply(query)
			response.Answer = []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: query.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)}}
			wire, err := response.Pack()
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := upstream.WriteTo(wire, peer); err != nil {
				return
			}
		}
	}()
	port := uint32(upstream.LocalAddr().(*net.UDPAddr).Port)
	r := new(router.Router)
	if err := r.Init(t.Context(), &router.Config{Rule: []*router.RoutingRule{
		{TargetTag: &router.RoutingRule_Tag{Tag: "business-tls"}, Protocol: []string{"tls"}},
		{TargetTag: &router.RoutingRule_Tag{Tag: "dns-route"}, InboundTag: []string{"dns-test"}, Networks: []xnet.Network{xnet.Network_UDP}, PortList: &xnet.PortList{Range: []*xnet.PortRange{{From: port, To: port}}}},
	}}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	dispatcher := &dnsRouteDispatcher{t: t, router: r, seen: make(chan dnsRouteDispatch, 8)}
	instance := new(core.Instance)
	if err := instance.AddFeature(dispatcher); err != nil {
		t.Fatal(err)
	}
	config := &appdns.Config{DisableCache: true, Tag: "dns-test", EnableParallelQuery: mode == "parallel", NameServer: []*appdns.NameServer{{Address: &xnet.Endpoint{Network: xnet.Network_UDP, Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: port}}}}
	if mode == "script" {
		config.Script = filepath.Join(t.TempDir(), "context.lua")
		if err := os.WriteFile(config.Script, []byte(`local server = require("xray.dns").Servers[1]
function HandleDNSQuery(domain, ipv4, ipv6, fake)
    return server:Query(domain, ipv4, ipv6, fake)
end`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	service, err := appdns.New(context.WithValue(t.Context(), core.XrayKey(1), instance), config)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	return service, instance, dispatcher.seen, received
}

// A panic in the singleflight/parallel worker must be a failed regression test, not a suite crash.
func TestDNSUDPContextWithoutCallerCore(t *testing.T) {
	if mode := os.Getenv("XRAY_DNS_CONTEXT_CHILD"); mode != "" {
		service, instance, seen, _ := dnsUDPContextFixture(t, mode, true)
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		ips, _, err := service.LookupIPContext(ctx, "without-core.invalid", featureDNS.IPOption{IPv4Enable: true})
		if err != nil || len(ips) != 1 || !ips[0].Equal(net.IPv4(192, 0, 2, 1)) {
			t.Fatalf("UDP lookup = %v, %v", ips, err)
		}
		select {
		case dispatched := <-seen:
			if core.FromContext(dispatched.ctx) != instance {
				t.Fatal("lookup lost service-owned core")
			}
		case <-ctx.Done():
			t.Fatal("query never reached UDP dispatcher")
		}
		return
	}
	for _, mode := range []string{"serial", "parallel", "script"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestDNSUDPContextWithoutCallerCore$", "-test.timeout=10s")
			cmd.Env = append(os.Environ(), "XRAY_DNS_CONTEXT_CHILD="+mode)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("lookup subprocess failed: %v\n%s", err, output)
			}
		})
	}
}

func TestDNSUDPContextUsesServiceCore(t *testing.T) {
	for _, mode := range []string{"serial", "parallel", "script"} {
		t.Run(mode, func(t *testing.T) {
			service, instance, seen, _ := dnsUDPContextFixture(t, mode, true)
			caller := context.WithValue(t.Context(), core.XrayKey(1), new(core.Instance))
			ctx, cancel := context.WithTimeout(caller, 2*time.Second)
			defer cancel()
			ips, _, err := service.LookupIPContext(ctx, "foreign-core.invalid", featureDNS.IPOption{IPv4Enable: true})
			if err != nil || len(ips) != 1 {
				t.Fatalf("UDP lookup = %v, %v", ips, err)
			}
			select {
			case dispatched := <-seen:
				if core.FromContext(dispatched.ctx) != instance {
					t.Fatal("lookup used caller core instead of service-owned core")
				}
			case <-ctx.Done():
				t.Fatal("query never reached UDP dispatcher")
			}
		})
	}
}

func TestDNSUDPContextRoutesIndependently(t *testing.T) {
	for _, mode := range []string{"serial", "parallel", "script"} {
		t.Run(mode, func(t *testing.T) {
			service, instance, seen, _ := dnsUDPContextFixture(t, mode, true)
			content := &session.Content{Protocol: "tls", SniffingRequest: session.SniffingRequest{Enabled: true, OverrideDestinationForProtocol: []string{"tls"}}, Attributes: map[string]string{"host": "business.invalid"}}
			original := *content
			original.Attributes = maps.Clone(content.Attributes)
			original.SniffingRequest.OverrideDestinationForProtocol = slices.Clone(content.SniffingRequest.OverrideDestinationForProtocol)
			ctx := session.ContextWithContent(context.WithValue(t.Context(), core.XrayKey(1), instance), content)
			var wg sync.WaitGroup
			for i := range 2 {
				wg.Go(func() {
					lookup, cancel := context.WithTimeout(ctx, 2*time.Second)
					defer cancel()
					ips, _, err := service.LookupIPContext(lookup, fmt.Sprintf("route-%d.invalid", i), featureDNS.IPOption{IPv4Enable: true})
					if err != nil || len(ips) != 1 {
						t.Errorf("UDP lookup = %v, %v", ips, err)
					}
				})
			}
			wg.Wait()
			select {
			case dispatched := <-seen:
				if dispatched.tag != "dns-route" {
					t.Errorf("UDP selected %q, want DNS tag/network/destination route", dispatched.tag)
				}
				dnsContent := session.ContentFromContext(dispatched.ctx)
				if dnsContent == content || dnsContent == nil || dnsContent.Protocol == "tls" || dnsContent.SniffingRequest.Enabled || len(dnsContent.Attributes) != 0 {
					t.Errorf("DNS dispatch inherited business Content: %+v", dnsContent)
				}
				if !dispatched.dest.Address.IP().Equal(net.IPv4(127, 0, 0, 1)) {
					t.Errorf("unexpected DNS destination %v", dispatched.dest)
				}
			default:
				t.Fatal("query never reached UDP dispatcher")
			}
			if !reflect.DeepEqual(content, &original) {
				t.Fatal("DNS changed caller Content")
			}
		})
	}
}

func TestDNSUDPContextPreservesCallerCancellation(t *testing.T) {
	for _, mode := range []string{"serial", "parallel", "script"} {
		for _, cause := range []string{"cancel", "deadline"} {
			t.Run(mode+"/"+cause, func(t *testing.T) {
				service, instance, seen, received := dnsUDPContextFixture(t, mode, false)
				request := context.WithValue(t.Context(), core.XrayKey(1), instance)
				ctx, cancel := context.WithTimeout(request, 700*time.Millisecond)
				defer cancel()
				done := make(chan error, 1)
				go func() {
					_, _, err := service.LookupIPContext(ctx, "blocked-udp.invalid", featureDNS.IPOption{IPv4Enable: true})
					done <- err
				}()
				var dispatched dnsRouteDispatch
				select {
				case dispatched = <-seen:
				case <-time.After(2 * time.Second):
					t.Fatal("UDP dispatch not started")
				}
				select {
				case <-received:
				case <-time.After(2 * time.Second):
					t.Fatal("real upstream did not receive query")
				}
				if cause == "cancel" {
					cancel()
				}
				select {
				case err := <-done:
					if !errors.Is(err, ctx.Err()) {
						t.Fatalf("lookup error = %v, context = %v", err, ctx.Err())
					}
				case <-time.After(2 * time.Second):
					t.Fatal("lookup ignored cancellation")
				}
				// The pooled UDP link outlives a query; its singleflight waiter must finish instead.
				if err := dispatched.ctx.Err(); err != nil {
					t.Fatalf("caller canceled shared UDP transport: %v", err)
				}
				next, cancelNext := context.WithTimeout(request, 2*time.Second)
				defer cancelNext()
				go func() {
					_, _, err := service.LookupIPContext(next, "blocked-udp.invalid", featureDNS.IPOption{IPv4Enable: true})
					done <- err
				}()
				select {
				case <-received:
				case <-next.Done():
					t.Fatal("canceled fetch worker did not release same-domain query")
				}
				cancelNext()
				select {
				case err := <-done:
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("second lookup = %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("second lookup waiter did not finish")
				}
			})
		}
	}
}

type dnsMuxSocketAttempt struct {
	ctx              context.Context
	network, address string
}

type dnsMuxSocketAdapter struct{ attempts chan dnsMuxSocketAttempt }

func (*dnsMuxSocketAdapter) Dial(string, string) (net.Conn, error) {
	return nil, errors.New("legacy socket adapter must not be used")
}

func (a *dnsMuxSocketAdapter) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	a.attempts <- dnsMuxSocketAttempt{ctx: ctx, network: network, address: address}
	<-ctx.Done()
	return nil, ctx.Err()
}

type dnsMuxXDNSOutbound struct {
	stream   *internet.MemoryStreamConfig
	started  chan context.Context
	cancel   chan context.CancelFunc
	finished chan error
}

func (p *dnsMuxXDNSOutbound) Process(ctx context.Context, _ *transport.Link, _ internet.Dialer) (err error) {
	p.started <- ctx
	defer func() { p.finished <- err }()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	p.cancel <- cancel
	ctx = session.ContextWithContent(ctx, &session.Content{Protocol: "tls", SniffingRequest: session.SniffingRequest{Enabled: true}})
	conn, err := p.stream.FinalMask.DialUDP(ctx, xnet.UDPDestination(xnet.IPAddress(net.IPv4(192, 0, 2, 9)), 9000))
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("mux-domain-bootstrap")); err != nil {
		return err
	}
	<-ctx.Done()
	return ctx.Err()
}

// The socket adapter stops after real Mux -> xdns -> DNS bootstrap, before a TLS handshake.
func TestDNSMuxXDNSDomainBootstrap(t *testing.T) {
	if mode := os.Getenv("XRAY_DNS_MUX_CHILD"); mode != "" {
		blockDNS := os.Getenv("XRAY_DNS_MUX_BLOCK_DNS") == "1"
		service, instance, seen, received := dnsUDPContextFixture(t, mode, !blockDNS)
		internet.InitSystemDialer(service, nil)
		t.Cleanup(func() { internet.InitSystemDialer(nil, nil) })
		adapter := &dnsMuxSocketAdapter{attempts: make(chan dnsMuxSocketAttempt, 8)}
		internet.UseAlternativeSystemDialer(internet.WithAdapter(adapter))
		t.Cleanup(func() { internet.UseAlternativeSystemDialer(nil) })
		stream, err := internet.ToMemoryStreamConfig(&internet.StreamConfig{
			SocketSettings: &internet.SocketConfig{DomainStrategy: internet.DomainStrategy_USE_IP4},
			Udpmasks: []*serial.TypedMessage{serial.ToTypedMessage(&xdns.Config{
				Domains:   []*xdns.DomainProto{{Name: "tunnel.invalid", LenLimit: 255, LabelLimit: 63, Types: []int32{16}}},
				Resolvers: []*xdns.ResolverProto{{Type: "tls", Addr: "resolver-bootstrap.invalid:853"}},
			})},
		})
		if err != nil {
			t.Fatal(err)
		}
		outbound := &dnsMuxXDNSOutbound{stream: stream, started: make(chan context.Context, 1), cancel: make(chan context.CancelFunc, 1), finished: make(chan error, 1)}
		factory := &mux.DialingWorkerFactory{Proxy: outbound, Strategy: mux.ClientStrategy{MaxConcurrency: 1}}
		worker, err := factory.Create()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = worker.Close() })
		select {
		case ctx := <-outbound.started:
			if core.FromContext(ctx) != nil || ctx.Done() == nil {
				t.Fatal("Mux did not supply the expected no-core cancellable context")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Mux outbound did not start")
		}
		cancel := <-outbound.cancel
		defer cancel()
		select {
		case dispatched := <-seen:
			if dispatched.tag != "dns-route" || core.FromContext(dispatched.ctx) != instance {
				t.Fatalf("Mux bootstrap route/core = %s/%p", dispatched.tag, core.FromContext(dispatched.ctx))
			}
		case <-time.After(2 * time.Second):
			t.Fatal("xdns resolver domain never reached real DNS dispatcher")
		}
		select {
		case <-received:
		case <-time.After(2 * time.Second):
			t.Fatal("xdns bootstrap emitted no real UDP DNS query")
		}
		var socket dnsMuxSocketAttempt
		if !blockDNS {
			select {
			case socket = <-adapter.attempts:
				if socket.network != "tcp" || socket.address != "192.0.2.1:853" {
					t.Fatalf("xdns bootstrap socket = %s %s", socket.network, socket.address)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("resolved resolver address did not reach socket adapter")
			}
		}
		cancel()
		select {
		case err := <-outbound.finished:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Mux outbound returned %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Mux/xdns Close did not cancel bootstrap worker")
		}
		if !blockDNS {
			select {
			case <-socket.ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("socket bootstrap lost Mux cancellation")
			}
		} else {
			select {
			case attempt := <-adapter.attempts:
				t.Fatalf("canceled DNS bootstrap opened socket %s", attempt.address)
			default:
			}
		}
		select {
		case <-worker.WaitClosed():
		case <-time.After(time.Second):
			t.Fatal("Mux client did not close")
		}
		return
	}
	for _, mode := range []string{"serial", "parallel", "script"} {
		for _, block := range []string{"0", "1"} {
			t.Run(mode+"/block-dns-"+block, func(t *testing.T) {
				cmd := exec.Command(os.Args[0], "-test.run=^TestDNSMuxXDNSDomainBootstrap$", "-test.timeout=12s")
				cmd.Env = append(os.Environ(), "XRAY_DNS_MUX_CHILD="+mode, "XRAY_DNS_MUX_BLOCK_DNS="+block)
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("Mux bootstrap subprocess failed: %v\n%s", err, output)
				}
			})
		}
	}
}
