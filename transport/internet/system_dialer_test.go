package internet_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask/xdns"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	"golang.org/x/net/dns/dnsmessage"
)

func useSystemTestResolver(t *testing.T, resolver *net.Resolver) {
	t.Helper()
	standard, common := net.DefaultResolver, xnet.DefaultResolver
	net.DefaultResolver, xnet.DefaultResolver = resolver, resolver
	t.Cleanup(func() { net.DefaultResolver, xnet.DefaultResolver = standard, common })
}

func blockSystemTestDNS(t *testing.T) (<-chan struct{}, <-chan struct{}) {
	t.Helper()
	started := make(chan struct{}, 1)
	cancelled := make(chan struct{}, 1)
	release := make(chan struct{})
	testCtx := t.Context()
	useSystemTestResolver(t, &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-ctx.Done():
			select {
			case cancelled <- struct{}{}:
			default:
			}
			return nil, ctx.Err()
		case <-release:
			return nil, errors.New("test DNS stopped")
		case <-testCtx.Done():
			return nil, errors.New("test finished")
		}
	}})
	t.Cleanup(func() { close(release) })
	return started, cancelled
}

func TestDefaultSystemDialerUDPResolutionCancellation(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			started, cancelled := blockSystemTestDNS(t)
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
				conn, err := (&internet.DefaultSystemDialer{}).Dial(ctx, nil, xnet.UDPDestination(xnet.DomainAddress("blocked.xdns-test.invalid"), 853), nil)
				if conn != nil {
					conn.Close()
				}
				done <- err
			}()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("system dial did not enter the configured DNS resolver")
			}
			if mode == "cancel" {
				cancel()
			}
			select {
			case err := <-done:
				if ctx.Err() == nil || !errors.Is(err, ctx.Err()) {
					t.Fatalf("cancelled DNS dial returned %v, context %v", err, ctx.Err())
				}
			case <-time.After(time.Second):
				t.Fatal("UDP hostname lookup ignored request cancellation")
			}
			select {
			case <-cancelled:
			case <-time.After(time.Second):
				t.Fatal("underlying DNS dial did not receive cancellation")
			}
		})
	}
}

func TestXDNSCloseCancelsProductionUDPHostnameLookup(t *testing.T) {
	started, cancelled := blockSystemTestDNS(t)
	mask := &xdns.Config{
		Domains:   []*xdns.DomainProto{{Name: "tunnel.test", LenLimit: 255, LabelLimit: 63, Types: []int32{16}, Edns0: 4096}},
		Resolvers: []*xdns.ResolverProto{{Type: "quic", Addr: "blocked.xdns-test.invalid:853"}},
	}
	settings, err := internet.ToMemoryStreamConfig(&internet.StreamConfig{Udpmasks: []*serial.TypedMessage{serial.ToTypedMessage(mask)}})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := settings.FinalMask.DialUDP(t.Context(), xnet.UDPDestination(xnet.LocalHostIP, 443))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if _, err := conn.Write([]byte("start DNS tunnel lookup")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("finalmask/xDNS path did not enter the production system DNS lookup")
	}
	done := make(chan error, 1)
	go func() { done <- conn.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("xdns Close did not cancel the production UDP hostname lookup")
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("xdns Close left the DNS dial running")
	}
}

func serveSystemTestDNS(t *testing.T, ipv4, ipv6 bool) {
	t.Helper()
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		var packet [512]byte
		for {
			n, addr, err := server.ReadFrom(packet[:])
			if err != nil {
				return
			}
			var request dnsmessage.Message
			if request.Unpack(packet[:n]) != nil {
				continue
			}
			response := dnsmessage.Message{Header: dnsmessage.Header{ID: request.ID, Response: true, Authoritative: true, RecursionDesired: request.RecursionDesired, RecursionAvailable: true}, Questions: request.Questions}
			for _, question := range request.Questions {
				resource := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: dnsmessage.ClassINET, TTL: 60}}
				if question.Type == dnsmessage.TypeA && ipv4 {
					resource.Body = &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}
				} else if question.Type == dnsmessage.TypeAAAA && ipv6 {
					resource.Body = &dnsmessage.AAAAResource{AAAA: [16]byte{15: 1}}
				} else {
					continue
				}
				response.Answers = append(response.Answers, resource)
			}
			if p, err := response.Pack(); err == nil {
				server.WriteTo(p, addr)
			}
		}
	}()
	useSystemTestResolver(t, &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.LocalAddr().String())
	}})
	t.Cleanup(func() { server.Close(); <-stopped })
}

func TestDefaultSystemDialerUDPAddressSelectionAndSocketControl(t *testing.T) {
	for _, mode := range []string{"dual-stack", "ipv6-only", "ipv4-literal", "ipv6-literal"} {
		t.Run(mode, func(t *testing.T) {
			want := net.ParseIP("127.0.0.1")
			network, address := "udp4", "127.0.0.1:0"
			if mode == "ipv6-only" || mode == "ipv6-literal" {
				want = net.ParseIP("::1")
				network, address = "udp6", "[::1]:0"
			}
			receiver, err := net.ListenPacket(network, address)
			if err != nil {
				if network == "udp6" {
					t.Skip("IPv6 sockets are unavailable")
				}
				t.Fatal(err)
			}
			defer receiver.Close()
			endpoint := receiver.LocalAddr().(*net.UDPAddr)
			serveSystemTestDNS(t, mode != "ipv6-only", true)
			destination := xnet.UDPDestination(xnet.DomainAddress("dual.xdns-test.invalid"), xnet.Port(endpoint.Port))
			if mode == "ipv4-literal" {
				destination.Address = xnet.LocalHostIP
			}
			if mode == "ipv6-literal" {
				destination.Address = xnet.LocalHostIPv6
			}
			var controlled atomic.Bool
			controllers := internet.Controllers
			internet.Controllers = append(append([]func(string, string, syscall.RawConn) error(nil), controllers...), func(network, address string, conn syscall.RawConn) error {
				if network != "udp4" && network != "udp6" {
					return errors.New("socket controller received a non-UDP network")
				}
				return conn.Control(func(fd uintptr) { controlled.Store(true) })
			})
			t.Cleanup(func() { internet.Controllers = controllers })
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			conn, err := (&internet.DefaultSystemDialer{}).Dial(ctx, nil, destination, &internet.SocketConfig{})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			remote := conn.RemoteAddr().(*net.UDPAddr)
			if !remote.IP.Equal(want) || remote.Port != endpoint.Port {
				t.Fatalf("resolved endpoint %v, want %v", remote, endpoint)
			}
			if !controlled.Load() {
				t.Fatal("UDP resolution bypassed existing socket control")
			}
			deadline := time.Now().Add(2 * time.Second)
			if err := receiver.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err := conn.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			payload := []byte{0, 255, 'U', 'D', 'P'}
			if n, err := conn.Write(payload); err != nil || n != len(payload) {
				t.Fatalf("UDP write = %d, %v", n, err)
			}
			var packet [32]byte
			n, source, err := receiver.ReadFrom(packet[:])
			if err != nil || !bytes.Equal(packet[:n], payload) {
				t.Fatalf("UDP receiver got %x, %v", packet[:n], err)
			}
			sender := source.(*net.UDPAddr)
			if !sender.IP.IsLoopback() || (sender.IP.To4() != nil) != (want.To4() != nil) {
				t.Fatalf("UDP packet source %v does not match the destination family", sender)
			}
			reply := []byte{128, 0, 'o', 'k'}
			if n, err := receiver.WriteTo(reply, source); err != nil || n != len(reply) {
				t.Fatalf("UDP reply = %d, %v", n, err)
			}
			n, err = conn.Read(packet[:])
			if err != nil || !bytes.Equal(packet[:n], reply) {
				t.Fatalf("system UDP socket received %x, %v", packet[:n], err)
			}
		})
	}
}

type systemLegacyAdapter struct {
	dial func(string, string) (net.Conn, error)
}

func (a *systemLegacyAdapter) Dial(network, address string) (net.Conn, error) {
	return a.dial(network, address)
}

type systemContextAdapter struct {
	*systemLegacyAdapter
	dialContext func(context.Context, string, string) (net.Conn, error)
}

func (a *systemContextAdapter) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return a.dialContext(ctx, network, address)
}

func TestSimpleSystemDialerLegacyAdapterStillDials(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			io.Copy(conn, conn)
		}
	}()
	t.Cleanup(func() { listener.Close(); <-stopped })
	adapter := &systemLegacyAdapter{dial: net.Dial}
	dest := xnet.DestinationFromAddr(listener.Addr())
	conn, err := internet.WithAdapter(adapter).Dial(context.Background(), nil, dest, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	payload := []byte{0, 255, 128}
	if n, err := conn.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("legacy adapter write = %d, %v", n, err)
	}
	var response [3]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil || !bytes.Equal(response[:], payload) {
		t.Fatalf("legacy adapter reply %x, %v", response, err)
	}
}

func TestSimpleSystemDialerContextAdapterCancelsRealLookup(t *testing.T) {
	started, cancelled := blockSystemTestDNS(t)
	var legacy atomic.Int32
	adapter := &systemContextAdapter{
		systemLegacyAdapter: &systemLegacyAdapter{dial: func(string, string) (net.Conn, error) {
			legacy.Add(1)
			return nil, errors.New("legacy adapter was called")
		}},
		dialContext: (&net.Dialer{}).DialContext,
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, err := internet.WithAdapter(adapter).Dial(ctx, nil, xnet.TCPDestination(xnet.DomainAddress("blocked.xdns-test.invalid"), 853), nil)
		if conn != nil {
			conn.Close()
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("context adapter did not reach real DNS lookup")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("context adapter returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("context adapter ignored cancellation")
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("DNS dial remained active after adapter cancellation")
	}
	if legacy.Load() != 0 {
		t.Fatal("context adapter fell back to legacy Dial")
	}
}

func systemAdapterTestMask(protocol, address string) *xdns.Config {
	return &xdns.Config{Domains: []*xdns.DomainProto{{Name: "tunnel.test", LenLimit: 255, LabelLimit: 63, Types: []int32{16}, Edns0: 4096}}, Resolvers: []*xdns.ResolverProto{{Type: protocol, Addr: address}}}
}

func TestLegacyAdapterRejectsEncryptedResolverDial(t *testing.T) {
	for _, protocol := range []string{"tls", "quic", "https", "https+h3"} {
		t.Run(protocol, func(t *testing.T) {
			var dialed atomic.Int32
			internet.UseAlternativeSystemDialer(internet.WithAdapter(&systemLegacyAdapter{dial: func(string, string) (net.Conn, error) {
				dialed.Add(1)
				return nil, errors.New("legacy dial should not start")
			}}))
			t.Cleanup(func() { internet.UseAlternativeSystemDialer(nil) })
			address := "127.0.0.1:853"
			if protocol == "https" || protocol == "https+h3" {
				address = "https://127.0.0.1/dns-query"
			}
			mask := systemAdapterTestMask(protocol, address)
			settings, err := internet.ToMemoryStreamConfig(&internet.StreamConfig{Udpmasks: []*serial.TypedMessage{serial.ToTypedMessage(mask)}})
			if err != nil {
				t.Fatal(err)
			}
			observed := &observedSystemDialer{SystemDialer: internet.WithAdapter(&systemLegacyAdapter{dial: func(string, string) (net.Conn, error) {
				dialed.Add(1)
				return nil, errors.New("legacy dial should not start")
			}}), entered: make(chan struct{}, 64), returned: make(chan error, 64)}
			internet.UseAlternativeSystemDialer(observed)
			conn, err := settings.FinalMask.DialUDP(t.Context(), xnet.UDPDestination(xnet.LocalHostIP, 443))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.Close() })
			if _, err := conn.Write([]byte("trigger strict dial rejection")); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-observed.returned:
				if err == nil {
					t.Fatal("unsupported adapter accepted an encrypted resolver dial")
				}
			case <-time.After(time.Second):
				t.Fatal("encrypted resolver did not attempt its runtime dial")
			}
			if dialed.Load() != 0 {
				t.Fatalf("encrypted resolver called legacy Dial %d times", dialed.Load())
			}
		})
	}
}

func TestContextAdapterEncryptedResolverCloseCancelsRealLookup(t *testing.T) {
	for _, protocol := range []string{"tls", "quic", "https", "https+h3"} {
		t.Run(protocol, func(t *testing.T) {
			started, cancelled := blockSystemTestDNS(t)
			adapter := &systemContextAdapter{systemLegacyAdapter: &systemLegacyAdapter{dial: func(string, string) (net.Conn, error) { return nil, errors.New("legacy dial should not start") }}, dialContext: (&net.Dialer{}).DialContext}
			internet.UseAlternativeSystemDialer(internet.WithAdapter(adapter))
			t.Cleanup(func() { internet.UseAlternativeSystemDialer(nil) })
			address := "blocked.xdns-test.invalid:853"
			if protocol == "https" || protocol == "https+h3" {
				address = "https://blocked.xdns-test.invalid/dns-query"
			}
			mask := systemAdapterTestMask(protocol, address)
			settings, err := internet.ToMemoryStreamConfig(&internet.StreamConfig{Udpmasks: []*serial.TypedMessage{serial.ToTypedMessage(mask)}})
			if err != nil {
				t.Fatal(err)
			}
			conn, err := settings.FinalMask.DialUDP(t.Context(), xnet.UDPDestination(xnet.LocalHostIP, 443))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.Close() })
			if _, err := conn.Write([]byte("trigger adapter DNS lookup")); err != nil {
				t.Fatal(err)
			}
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("encrypted resolver did not enter adapter lookup")
			}
			done := make(chan error, 1)
			go func() { done <- conn.Close() }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("encrypted resolver Close did not cancel adapter lookup")
			}
			select {
			case <-cancelled:
			case <-time.After(time.Second):
				t.Fatal("adapter DNS dial stayed active after Close")
			}
		})
	}
}

func TestLegacyAdapterStillSupportsPlainResolvers(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp"} {
		t.Run(protocol, func(t *testing.T) {
			var endpoint net.Addr
			if protocol == "udp" {
				listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				endpoint = listener.LocalAddr()
			} else {
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				endpoint = listener.Addr()
			}
			var opened net.Conn
			adapter := &systemLegacyAdapter{dial: func(network, address string) (net.Conn, error) {
				conn, err := net.Dial(network, address)
				if err != nil {
					return nil, err
				}
				opened = conn
				if packet, ok := conn.(net.PacketConn); ok {
					return &xnet.PacketConnWrapper{PacketConn: packet, Dest: conn.RemoteAddr()}, nil
				}
				return conn, nil
			}}
			internet.UseAlternativeSystemDialer(internet.WithAdapter(adapter))
			t.Cleanup(func() { internet.UseAlternativeSystemDialer(nil) })
			mask := systemAdapterTestMask(protocol, endpoint.String())
			settings, err := internet.ToMemoryStreamConfig(&internet.StreamConfig{Udpmasks: []*serial.TypedMessage{serial.ToTypedMessage(mask)}})
			if err != nil {
				t.Fatal(err)
			}
			conn, err := settings.FinalMask.DialUDP(t.Context(), xnet.UDPDestination(xnet.LocalHostIP, 443))
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			if opened == nil {
				t.Fatal("plain resolver did not use legacy callback")
			}
			opened.SetReadDeadline(time.Now())
			if _, err := opened.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("plain resolver Close left adapter socket open: %v", err)
			}
		})
	}
}
