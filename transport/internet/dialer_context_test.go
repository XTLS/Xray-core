package internet_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	fdns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/finalmask/xdns"
)

type dialerLegacyDNS struct {
	lookup func(string, fdns.IPOption) ([]net.IP, uint32, error)
}

func (*dialerLegacyDNS) Type() interface{} { return fdns.ClientType() }
func (*dialerLegacyDNS) Start() error      { return nil }
func (*dialerLegacyDNS) Close() error      { return nil }
func (c *dialerLegacyDNS) LookupIP(domain string, option fdns.IPOption) ([]net.IP, uint32, error) {
	return c.lookup(domain, option)
}

type dialerContextDNS struct {
	*dialerLegacyDNS
	lookupContext func(context.Context, string, fdns.IPOption) ([]net.IP, uint32, error)
}

func (c *dialerContextDNS) LookupIPContext(ctx context.Context, domain string, option fdns.IPOption) ([]net.IP, uint32, error) {
	return c.lookupContext(ctx, domain, option)
}

func useDialerTestDNS(t *testing.T, client fdns.Client) {
	t.Helper()
	internet.InitSystemDialer(client, nil)
	t.Cleanup(func() { internet.InitSystemDialer(nil, nil) })
}

func watchDialerTestSockets(t *testing.T) *atomic.Int32 {
	t.Helper()
	count := new(atomic.Int32)
	controllers := internet.Controllers
	internet.Controllers = append(append([]func(string, string, syscall.RawConn) error(nil), controllers...), func(network, address string, conn syscall.RawConn) error { count.Add(1); return nil })
	t.Cleanup(func() { internet.Controllers = controllers })
	return count
}

func TestLookupForIPContextPreservesFallbackAndSourceFamilies(t *testing.T) {
	ipv4, ipv6 := fdns.IPOption{IPv4Enable: true}, fdns.IPOption{IPv6Enable: true}
	for _, test := range []struct {
		name     string
		strategy internet.DomainStrategy
		source   xnet.Address
		options  []fdns.IPOption
		want     string
	}{
		{"v4-v6", internet.DomainStrategy_USE_IP46, nil, []fdns.IPOption{ipv4, ipv6}, "::1"},
		{"v6-v4", internet.DomainStrategy_USE_IP64, nil, []fdns.IPOption{ipv6, ipv4}, "127.0.0.1"},
		{"source-v4", internet.DomainStrategy_USE_IP46, xnet.LocalHostIP, []fdns.IPOption{ipv4}, "127.0.0.1"},
		{"source-v6", internet.DomainStrategy_USE_IP46, xnet.LocalHostIPv6, []fdns.IPOption{ipv6}, "::1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var seen []fdns.IPOption
			client := &dialerContextDNS{dialerLegacyDNS: &dialerLegacyDNS{lookup: func(string, fdns.IPOption) ([]net.IP, uint32, error) {
				return nil, 0, errors.New("legacy lookup must not be used")
			}}}
			client.lookupContext = func(ctx context.Context, domain string, option fdns.IPOption) ([]net.IP, uint32, error) {
				seen = append(seen, option)
				if len(seen) < len(test.options) {
					return nil, 0, nil
				}
				return []net.IP{net.ParseIP(test.want)}, 60, nil
			}
			useDialerTestDNS(t, client)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			ips, err := internet.LookupForIPContext(ctx, "options.test", test.strategy, test.source)
			if err != nil || len(ips) != 1 || !ips[0].Equal(net.ParseIP(test.want)) {
				t.Fatalf("lookup returned %v, %v", ips, err)
			}
			if len(seen) != len(test.options) {
				t.Fatalf("lookup count %d, want %d", len(seen), len(test.options))
			}
			for i := range seen {
				if seen[i] != test.options[i] {
					t.Fatalf("lookup option %v, want %v", seen[i], test.options[i])
				}
			}
		})
	}
}

func TestLookupForIPContextCancellationPreventsFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var calls int
	client := &dialerContextDNS{dialerLegacyDNS: &dialerLegacyDNS{lookup: func(string, fdns.IPOption) ([]net.IP, uint32, error) {
		t.Fatal("legacy lookup was used")
		return nil, 0, nil
	}}}
	client.lookupContext = func(context.Context, string, fdns.IPOption) ([]net.IP, uint32, error) {
		calls++
		cancel()
		return nil, 0, nil
	}
	useDialerTestDNS(t, client)
	if _, err := internet.LookupForIPContext(ctx, "cancel.test", internet.DomainStrategy_USE_IP46, nil); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("cancelled lookup returned %v after %d calls", err, calls)
	}
}

func TestLookupForIPContextUsesLegacyClientForOrdinaryTCPAndUDP(t *testing.T) {
	var calls atomic.Int32
	client := &dialerLegacyDNS{lookup: func(string, fdns.IPOption) ([]net.IP, uint32, error) {
		calls.Add(1)
		return []net.IP{net.ParseIP("127.0.0.1")}, 60, nil
	}}
	useDialerTestDNS(t, client)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	t.Run("tcp", func(t *testing.T) {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		accepted := make(chan struct{})
		go func() {
			conn, err := listener.Accept()
			if err == nil {
				conn.Close()
				close(accepted)
			}
		}()
		conn, err := internet.DialSystem(ctx, xnet.TCPDestination(xnet.DomainAddress("legacy.test"), xnet.Port(listener.Addr().(*net.TCPAddr).Port)), &internet.SocketConfig{DomainStrategy: internet.DomainStrategy_USE_IP4})
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
		select {
		case <-accepted:
		case <-time.After(time.Second):
			t.Fatal("legacy DNS result did not reach the TCP listener")
		}
	})

	t.Run("udp", func(t *testing.T) {
		receiver, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer receiver.Close()
		conn, err := internet.DialSystem(ctx, xnet.UDPDestination(xnet.DomainAddress("legacy.test"), xnet.Port(receiver.LocalAddr().(*net.UDPAddr).Port)), &internet.SocketConfig{DomainStrategy: internet.DomainStrategy_USE_IP4})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		payload := []byte("legacy DNS UDP")
		if n, err := conn.Write(payload); err != nil || n != len(payload) {
			t.Fatalf("UDP write = %d, %v", n, err)
		}
		receiver.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, len(payload))
		n, _, err := receiver.ReadFrom(buf)
		if err != nil || !bytes.Equal(buf[:n], payload) {
			t.Fatalf("UDP packet = %q, %v", buf[:n], err)
		}
	})
	if got := calls.Load(); got != 2 {
		t.Fatalf("legacy DNS calls = %d, want one per transport", got)
	}
}

func TestDialSystemDomainStrategyCancellationDoesNotOpenSocket(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			serveSystemTestDNS(t, true, true)
			entered := make(chan struct{}, 1)
			var calls atomic.Int32
			client := &dialerContextDNS{dialerLegacyDNS: &dialerLegacyDNS{lookup: func(string, fdns.IPOption) ([]net.IP, uint32, error) {
				return nil, 0, errors.New("legacy lookup was used")
			}}}
			client.lookupContext = func(ctx context.Context, domain string, option fdns.IPOption) ([]net.IP, uint32, error) {
				calls.Add(1)
				entered <- struct{}{}
				<-ctx.Done()
				return nil, 0, ctx.Err()
			}
			useDialerTestDNS(t, client)
			sockets := watchDialerTestSockets(t)
			var ctx context.Context
			var cancel context.CancelFunc
			if mode == "deadline" {
				ctx, cancel = context.WithTimeout(t.Context(), 500*time.Millisecond)
			} else {
				ctx, cancel = context.WithCancel(t.Context())
			}
			defer cancel()
			done := make(chan error, 1)
			go func() {
				conn, err := internet.DialSystem(ctx, xnet.UDPDestination(xnet.DomainAddress("cancel.xdns-test.invalid"), 853), &internet.SocketConfig{DomainStrategy: internet.DomainStrategy_USE_IP46})
				if conn != nil {
					conn.Close()
				}
				done <- err
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("DialSystem did not use ContextClient")
			}
			if mode == "cancel" {
				cancel()
			}
			select {
			case err := <-done:
				if ctx.Err() == nil || !errors.Is(err, ctx.Err()) {
					t.Fatalf("cancelled dial returned %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("DomainStrategy dial ignored cancellation")
			}
			if calls.Load() != 1 || sockets.Load() != 0 {
				t.Fatalf("cancellation caused fallback or opened a socket: calls=%d, sockets=%d", calls.Load(), sockets.Load())
			}
		})
	}
}

func TestDialSystemSRVLookupCancellationDoesNotOpenSocket(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			started, _ := blockSystemTestDNS(t)
			sockets := watchDialerTestSockets(t)
			var ctx context.Context
			var cancel context.CancelFunc
			if mode == "deadline" {
				ctx, cancel = context.WithTimeout(t.Context(), 500*time.Millisecond)
			} else {
				ctx, cancel = context.WithCancel(t.Context())
			}
			defer cancel()
			done := make(chan error, 1)
			go func() {
				conn, err := internet.DialSystem(ctx, xnet.UDPDestination(xnet.DomainAddress("_dns._udp.blocked.invalid"), 853), &internet.SocketConfig{AddressPortStrategy: internet.AddressPortStrategy_SrvPortAndAddress})
				if conn != nil {
					conn.Close()
				}
				done <- err
			}()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("SRV lookup did not enter controlled resolver")
			}
			if mode == "cancel" {
				cancel()
			}
			select {
			case err := <-done:
				if ctx.Err() == nil || !errors.Is(err, ctx.Err()) {
					t.Fatalf("cancelled SRV dial returned %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("SRV lookup ignored cancellation")
			}
			if sockets.Load() != 0 {
				t.Fatal("cancelled SRV lookup opened an outbound socket")
			}
		})
	}
}

func TestXDNSCloseCancelsDomainStrategyAndSRVLookups(t *testing.T) {
	for _, mode := range []string{"domain", "srv"} {
		t.Run(mode, func(t *testing.T) {
			var started <-chan struct{}
			host := "blocked.xdns-test.invalid:853"
			options := &internet.SocketConfig{DomainStrategy: internet.DomainStrategy_USE_IP46}
			if mode == "srv" {
				started, _ = blockSystemTestDNS(t)
				host = "_dns._udp.blocked.invalid:853"
				options = &internet.SocketConfig{AddressPortStrategy: internet.AddressPortStrategy_SrvPortAndAddress}
			} else {
				entered := make(chan struct{}, 1)
				started = entered
				client := &dialerContextDNS{dialerLegacyDNS: &dialerLegacyDNS{lookup: func(string, fdns.IPOption) ([]net.IP, uint32, error) {
					return nil, 0, errors.New("legacy lookup was used")
				}}}
				client.lookupContext = func(ctx context.Context, domain string, option fdns.IPOption) ([]net.IP, uint32, error) {
					entered <- struct{}{}
					<-ctx.Done()
					return nil, 0, ctx.Err()
				}
				useDialerTestDNS(t, client)
			}
			mask := &xdns.Config{Domains: []*xdns.DomainProto{{Name: "tunnel.test", LenLimit: 255, LabelLimit: 63, Types: []int32{16}, Edns0: 4096}}, Resolvers: []*xdns.ResolverProto{{Type: "quic", Addr: host, ServerName: "resolver.test"}}}
			settings, err := internet.ToMemoryStreamConfig(&internet.StreamConfig{SocketSettings: options, Udpmasks: []*serial.TypedMessage{serial.ToTypedMessage(mask)}})
			if err != nil {
				t.Fatal(err)
			}
			conn, err := settings.FinalMask.DialUDP(t.Context(), xnet.UDPDestination(xnet.LocalHostIP, 443))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.Close() })
			if _, err := conn.Write([]byte("start controlled lookup")); err != nil {
				t.Fatal(err)
			}
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("xdns did not enter controlled lookup")
			}
			done := make(chan error, 1)
			go func() { done <- conn.Close() }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("xdns Close did not cancel lookup")
			}
		})
	}
}

func TestDialSystemContextLookupPreservesOutboundGatewayAndSocketControl(t *testing.T) {
	receiver, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	endpoint := receiver.LocalAddr().(*net.UDPAddr)
	var seen fdns.IPOption
	client := &dialerContextDNS{dialerLegacyDNS: &dialerLegacyDNS{lookup: func(string, fdns.IPOption) ([]net.IP, uint32, error) {
		return nil, 0, errors.New("legacy lookup was used")
	}}}
	client.lookupContext = func(ctx context.Context, domain string, option fdns.IPOption) ([]net.IP, uint32, error) {
		seen = option
		return []net.IP{net.ParseIP("127.0.0.1")}, 60, nil
	}
	useDialerTestDNS(t, client)
	sockets := watchDialerTestSockets(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Name: "freedom", Gateway: xnet.LocalHostIP}})
	conn, err := internet.DialSystem(ctx, xnet.UDPDestination(xnet.DomainAddress("gateway.test"), xnet.Port(endpoint.Port)), &internet.SocketConfig{DomainStrategy: internet.DomainStrategy_USE_IP64})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if seen != (fdns.IPOption{IPv4Enable: true}) || sockets.Load() != 1 {
		t.Fatalf("gateway family or socket control changed: %v, sockets=%d", seen, sockets.Load())
	}
	payload := []byte{0, 255, 128}
	if n, err := conn.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("gateway write = %d, %v", n, err)
	}
	receiver.SetReadDeadline(time.Now().Add(time.Second))
	var packet [16]byte
	n, source, err := receiver.ReadFrom(packet[:])
	if err != nil || !bytes.Equal(packet[:n], payload) {
		t.Fatalf("gateway packet %x, %v", packet[:n], err)
	}
	if !source.(*net.UDPAddr).IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("outbound gateway was lost: %v", source)
	}
}

func TestLookupForIPContextRejectsLegacyClientForRequiredCancellation(t *testing.T) {
	var calls atomic.Int32
	useDialerTestDNS(t, &dialerLegacyDNS{lookup: func(string, fdns.IPOption) ([]net.IP, uint32, error) {
		calls.Add(1)
		return []net.IP{net.ParseIP("127.0.0.1")}, 60, nil
	}})
	ctx, cancel := context.WithCancel(finalmask.ContextWithRequiredDial(t.Context()))
	defer cancel()
	if _, err := internet.LookupForIPContext(ctx, "strict.test", internet.DomainStrategy_USE_IP46, nil); err == nil {
		t.Fatal("strict dial accepted a legacy DNS client")
	}
	if calls.Load() != 0 {
		t.Fatal("strict dial entered a legacy DNS lookup")
	}
}
