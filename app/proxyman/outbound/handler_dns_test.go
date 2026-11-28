package outbound

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	wireDNS "github.com/miekg/dns"
	"github.com/xtls/xray-core/app/dispatcher"
	appDNS "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type targetStrategyTestDNS struct {
	dns.Client
	waiting chan struct{}
	calls   int
}

func (d *targetStrategyTestDNS) LookupIP(string, dns.IPOption) ([]net.IP, uint32, error) {
	return nil, 0, errors.New("unexpected contextless lookup")
}

func (d *targetStrategyTestDNS) LookupIPContext(ctx context.Context, _ string, _ dns.IPOption) ([]net.IP, uint32, error) {
	d.calls++
	if d.calls == 1 {
		close(d.waiting)
		<-ctx.Done()
		return nil, 0, ctx.Err()
	}
	return []net.IP{net.ParseIP("127.0.0.1")}, 60, nil
}

type targetStrategyTestOutbound struct {
	destinations chan net.Destination
}

func (p targetStrategyTestOutbound) Process(ctx context.Context, _ *transport.Link, _ internet.Dialer) error {
	p.destinations <- session.OutboundsFromContext(ctx)[0].Target
	return nil
}

type targetStrategyTestEndpoint struct {
	interrupted bool
}

func (e *targetStrategyTestEndpoint) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return nil, nil
}

func (e *targetStrategyTestEndpoint) WriteMultiBuffer(buf.MultiBuffer) error {
	return nil
}

func (e *targetStrategyTestEndpoint) Interrupt() {
	e.interrupted = true
}

func TestDispatchTargetStrategyStopsCanceledRoute(t *testing.T) {
	for _, strategy := range []internet.DomainStrategy{internet.DomainStrategy_USE_IP46, internet.DomainStrategy_FORCE_IP46} {
		t.Run(strategy.String(), func(t *testing.T) {
			resolver := &targetStrategyTestDNS{waiting: make(chan struct{})}
			internet.InitSystemDialer(resolver, nil)
			t.Cleanup(func() { internet.InitSystemDialer(nil, nil) })

			proxy := targetStrategyTestOutbound{destinations: make(chan net.Destination, 1)}
			handler := &Handler{senderSettings: &proxyman.SenderConfig{TargetStrategy: strategy}, proxy: proxy}
			target := net.TCPDestination(net.DomainAddress("controlled.example"), 8080)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			route, stop := context.WithCancel(session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: target}}))
			defer stop()
			in, out := new(targetStrategyTestEndpoint), new(targetStrategyTestEndpoint)

			done := make(chan struct{})
			go func() {
				defer close(done)
				handler.Dispatch(route, &transport.Link{Reader: in, Writer: out})
			}()
			select {
			case <-resolver.waiting:
			case <-ctx.Done():
				t.Fatal("targetStrategy did not call the context-aware resolver")
			}
			stop()
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("outbound handler did not return after cancellation")
			}
			if resolver.calls != 1 || !in.interrupted || !out.interrupted {
				t.Fatalf("cancellation caused %d DNS calls, interrupted reader=%v, writer=%v",
					resolver.calls, in.interrupted, out.interrupted)
			}
			select {
			case dest := <-proxy.destinations:
				t.Fatalf("canceled route launched outbound processing to %v", dest)
			default:
			}

			live := session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: target}})
			handler.Dispatch(live, &transport.Link{Reader: new(targetStrategyTestEndpoint), Writer: new(targetStrategyTestEndpoint)})
			select {
			case dest := <-proxy.destinations:
				if want := net.TCPDestination(net.LocalHostIP, 8080); dest != want {
					t.Fatalf("live route target = %v, want %v", dest, want)
				}
			default:
				t.Fatal("successful resolution did not launch outbound processing")
			}
		})
	}
}

func withNativeDNSWait(t *testing.T, check func(context.Context, <-chan struct{}, func(), net.Destination)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	defer cancel()

	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.LocalHostIP.IP()})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	waiting, release := make(chan struct{}), make(chan struct{})
	var requestSeen, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	upstream := &wireDNS.Server{
		PacketConn: socket,
		Handler: wireDNS.HandlerFunc(func(w wireDNS.ResponseWriter, req *wireDNS.Msg) {
			requestSeen.Do(func() { close(waiting) })
			select {
			case <-ctx.Done():
				return
			case <-release:
			}
			response := new(wireDNS.Msg).SetReply(req)
			response.Answer = []wireDNS.RR{&wireDNS.A{
				Hdr: wireDNS.RR_Header{Name: req.Question[0].Name, Rrtype: wireDNS.TypeA, Class: wireDNS.ClassINET, Ttl: 60},
				A:   net.LocalHostIP.IP(),
			}}
			w.WriteMsg(response)
		}),
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- upstream.ActivateAndServe() }()
	defer func() {
		unblock()
		upstream.Shutdown()
		select {
		case <-serverDone:
		case <-ctx.Done():
			t.Error("loopback nameserver did not shut down")
		}
	}()

	instance, err := core.New(&core.Config{App: []*serial.TypedMessage{
		serial.ToTypedMessage(&appDNS.Config{
			NameServer: []*appDNS.NameServer{{
				Address: &net.Endpoint{Address: &net.IPOrDomain{Address: &net.IPOrDomain_Domain{
					Domain: "udp+local://" + socket.LocalAddr().String(),
				}}},
				TimeoutMs: 4500,
			}},
			QueryStrategy: appDNS.QueryStrategy_USE_IP4,
		}),
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		serial.ToTypedMessage(&policy.Config{}),
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	defer internet.InitSystemDialer(nil, nil)
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}

	check(ctx, waiting, unblock, net.DestinationFromAddr(socket.LocalAddr()))
}

func TestDispatchTargetStrategyCancelsNativeDNSWait(t *testing.T) {
	withNativeDNSWait(t, func(ctx context.Context, waiting <-chan struct{}, unblock func(), _ net.Destination) {
		proxy := targetStrategyTestOutbound{destinations: make(chan net.Destination, 2)}
		handler := &Handler{
			senderSettings: &proxyman.SenderConfig{TargetStrategy: internet.DomainStrategy_FORCE_IP4},
			proxy:          proxy,
		}
		target := net.TCPDestination(net.DomainAddress("controlled.example"), 8080)
		route, stop := context.WithCancel(session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: target}}))
		defer stop()
		in, out := new(targetStrategyTestEndpoint), new(targetStrategyTestEndpoint)
		dispatchDone := make(chan struct{})
		go func() {
			defer close(dispatchDone)
			handler.Dispatch(route, &transport.Link{Reader: in, Writer: out})
		}()
		select {
		case <-waiting:
		case <-ctx.Done():
			t.Fatal("targetStrategy did not query the loopback nameserver")
		}
		stop()
		select {
		case <-dispatchDone:
		case <-time.After(time.Second):
			t.Fatal("outbound waited for the nameserver response after cancellation")
		}
		if !in.interrupted || !out.interrupted || len(proxy.destinations) != 0 {
			t.Fatal("canceled route retained the link or started proxy processing")
		}

		live := session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: target}})
		unblock()
		handler.Dispatch(live, &transport.Link{Reader: new(targetStrategyTestEndpoint), Writer: new(targetStrategyTestEndpoint)})
		select {
		case dest := <-proxy.destinations:
			if want := net.TCPDestination(net.LocalHostIP, 8080); dest != want {
				t.Fatalf("live route target = %v, want %v", dest, want)
			}
		default:
			t.Fatal("the nameserver response did not reach the live route")
		}
	})
}

type routeLookupSocketDialer struct {
	internet.DefaultSystemDialer
	nameserver net.Destination
	started    chan net.Destination
}

func (d *routeLookupSocketDialer) Dial(ctx context.Context, source net.Address, target net.Destination, opts *internet.SocketConfig) (net.Conn, error) {
	if target != d.nameserver {
		d.started <- target
	}
	return d.DefaultSystemDialer.Dial(ctx, source, target, opts)
}

func TestDialSystemDomainStrategyCancelsNativeDNSWait(t *testing.T) {
	withNativeDNSWait(t, func(ctx context.Context, waiting <-chan struct{}, unblock func(), nameserver net.Destination) {
		dialer := &routeLookupSocketDialer{nameserver: nameserver, started: make(chan net.Destination, 4)}
		internet.UseAlternativeSystemDialer(dialer)
		defer internet.UseAlternativeSystemDialer(nil)

		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.LocalHostIP.IP()})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		peer := net.DestinationFromAddr(listener.Addr())
		target := net.TCPDestination(net.DomainAddress("controlled.example"), peer.Port)
		opts := &internet.SocketConfig{DomainStrategy: internet.DomainStrategy_USE_IP46}
		route, stop := context.WithCancel(ctx)
		done := make(chan error, 1)
		finished := make(chan struct{})
		go func() {
			defer close(finished)
			conn, err := internet.DialSystem(route, target, opts)
			if conn != nil {
				conn.Close()
				err = errors.New("canceled route opened a destination socket")
			}
			done <- err
		}()
		defer func() {
			stop()
			unblock()
			<-finished
		}()

		select {
		case <-waiting:
		case <-ctx.Done():
			t.Fatal("DialSystem did not query the loopback nameserver")
		}
		stop()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled DialSystem = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("DialSystem did not return before the nameserver response")
		}
		select {
		case started := <-dialer.started:
			t.Fatalf("canceled route tried to open a socket for %v", started)
		default:
		}

		unblock()
		conn, err := internet.DialSystem(ctx, target, opts)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if got := conn.RemoteAddr().String(); got != listener.Addr().String() {
			t.Fatalf("live route connected to %s, want %s", got, listener.Addr())
		}
		select {
		case started := <-dialer.started:
			if started != peer {
				t.Fatalf("live socket target = %v, want %v", started, peer)
			}
		default:
			t.Fatal("live route did not start a socket dial")
		}
	})
}
