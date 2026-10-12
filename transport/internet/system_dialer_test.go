package internet_test

import (
	"context"
	"errors"
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
		select { case started <- struct{}{}: default: }
		select {
		case <-ctx.Done():
			select { case cancelled <- struct{}{}: default: }
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
				if conn != nil { conn.Close() }
				done <- err
			}()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("system dial did not enter the configured DNS resolver")
			}
			if mode == "cancel" { cancel() }
			select {
			case err := <-done:
				if ctx.Err() == nil || !errors.Is(err, ctx.Err()) { t.Fatalf("cancelled DNS dial returned %v, context %v", err, ctx.Err()) }
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
		Domains: []*xdns.DomainProto{{Name: "tunnel.test", LenLimit: 255, LabelLimit: 63, Types: []int32{16}, Edns0: 4096}},
		Resolvers: []*xdns.ResolverProto{{Type: "quic", Addr: "blocked.xdns-test.invalid:853"}},
	}
	settings, err := internet.ToMemoryStreamConfig(&internet.StreamConfig{Udpmasks: []*serial.TypedMessage{serial.ToTypedMessage(mask)}})
	if err != nil { t.Fatal(err) }
	conn, err := settings.FinalMask.DialUDP(t.Context(), xnet.UDPDestination(xnet.LocalHostIP, 443))
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { conn.Close() })
	if _, err := conn.Write([]byte("start DNS tunnel lookup")); err != nil { t.Fatal(err) }
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("finalmask/xDNS path did not enter the production system DNS lookup")
	}
	done := make(chan error, 1)
	go func() { done <- conn.Close() }()
	select {
	case err := <-done:
		if err != nil { t.Fatal(err) }
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
	if err != nil { t.Fatal(err) }
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		var packet [512]byte
		for {
			n, addr, err := server.ReadFrom(packet[:])
			if err != nil { return }
			var request dnsmessage.Message
			if request.Unpack(packet[:n]) != nil { continue }
			response := dnsmessage.Message{Header: dnsmessage.Header{ID: request.ID, Response: true, Authoritative: true, RecursionDesired: request.RecursionDesired, RecursionAvailable: true}, Questions: request.Questions}
			for _, question := range request.Questions {
				resource := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: dnsmessage.ClassINET, TTL: 60}}
				if question.Type == dnsmessage.TypeA && ipv4 {
					resource.Body = &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}
				} else if question.Type == dnsmessage.TypeAAAA && ipv6 {
					resource.Body = &dnsmessage.AAAAResource{AAAA: [16]byte{15: 1}}
				} else { continue }
				response.Answers = append(response.Answers, resource)
			}
			if p, err := response.Pack(); err == nil { server.WriteTo(p, addr) }
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
			if mode == "ipv6-only" || mode == "ipv6-literal" {
				probe, err := net.ListenPacket("udp6", "[::1]:0")
				if err != nil { t.Skip("IPv6 sockets are unavailable") }
				probe.Close()
			}
			serveSystemTestDNS(t, mode != "ipv6-only", true)
			destination := xnet.UDPDestination(xnet.DomainAddress("dual.xdns-test.invalid"), 853)
			want := net.ParseIP("127.0.0.1")
			if mode == "ipv4-literal" { destination.Address = xnet.LocalHostIP }
			if mode == "ipv6-only" || mode == "ipv6-literal" { want = net.ParseIP("::1") }
			if mode == "ipv6-literal" { destination.Address = xnet.LocalHostIPv6 }
			var controlled atomic.Bool
			controllers := internet.Controllers
			internet.Controllers = append(append([]func(string, string, syscall.RawConn) error(nil), controllers...), func(network, address string, conn syscall.RawConn) error { controlled.Store(true); return nil })
			t.Cleanup(func() { internet.Controllers = controllers })
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			conn, err := (&internet.DefaultSystemDialer{}).Dial(ctx, nil, destination, &internet.SocketConfig{})
			if err != nil { t.Fatal(err) }
			defer conn.Close()
			remote := conn.RemoteAddr().(*net.UDPAddr)
			if !remote.IP.Equal(want) || remote.Port != 853 { t.Fatalf("resolved endpoint %v, want %v:853", remote, want) }
			local := conn.LocalAddr().(*net.UDPAddr)
			if (local.IP.To4() != nil) != (want.To4() != nil) { t.Fatalf("local socket family %v differs from destination %v", local, remote) }
			if !controlled.Load() { t.Fatal("UDP resolution bypassed existing socket control") }
		})
	}
}
