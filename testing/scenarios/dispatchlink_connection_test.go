package scenarios

import (
	"context"
	"errors"
	"io"
	stdnet "net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	wireDNS "github.com/miekg/dns"
	appDNS "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/loopback"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tagged"
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"
	"golang.org/x/net/http2"
)

func TestCoreDialAndRoutedDNSTCP(t *testing.T) {
	ctx, stop := context.WithTimeout(t.Context(), 8*time.Second)
	defer stop()
	stub, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	queried := make(chan struct{})
	release := make(chan struct{})
	var queryCount atomic.Int32
	var releaseOnce sync.Once
	finishAnswer := func() { releaseOnce.Do(func() { close(release) }) }
	dnsServer := &wireDNS.Server{
		Listener: stub,
		Net:      "tcp",
		Handler: wireDNS.HandlerFunc(func(w wireDNS.ResponseWriter, msg *wireDNS.Msg) {
			if queryCount.Add(1) == 1 {
				close(queried)
				select {
				case <-release:
				case <-ctx.Done():
					return
				}
			}
			answer := new(wireDNS.Msg)
			answer.SetReply(msg)
			answer.Answer = []wireDNS.RR{&wireDNS.A{
				Hdr: wireDNS.RR_Header{Name: msg.Question[0].Name, Rrtype: wireDNS.TypeA, Class: wireDNS.ClassINET, Ttl: 30},
				A:   stdnet.IPv4(192, 0, 2, 34),
			}}
			_ = w.WriteMsg(answer)
		}),
	}
	serverReady := make(chan struct{})
	dnsServer.NotifyStartedFunc = func() { close(serverReady) }
	dnsDone := make(chan error, 1)
	go func() { dnsDone <- dnsServer.ActivateAndServe() }()
	defer func() {
		finishAnswer()
		_ = dnsServer.ShutdownContext(ctx)
		_ = stub.Close()
		select {
		case <-dnsDone:
		case <-ctx.Done():
			t.Error("TCP DNS server did not exit")
		}
	}()
	select {
	case <-serverReady:
	case err := <-dnsDone:
		dnsDone <- err
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	origin, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	exchanged := make(chan error, 1)
	go func() {
		peer, err := origin.Accept()
		if err != nil {
			exchanged <- err
			return
		}
		defer peer.Close()
		_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.WriteString(peer, "ready"); err != nil {
			exchanged <- err
			return
		}
		var request [4]byte
		if _, err := io.ReadFull(peer, request[:]); err != nil {
			exchanged <- err
			return
		}
		_, err = peer.Write(request[:])
		exchanged <- err
	}()

	config := withDefaultApps(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&appDNS.Config{
				NameServer: []*appDNS.NameServer{{
					Address:   &net.Endpoint{Address: net.NewIPOrDomain(net.DomainAddress("tcp://" + stub.Addr().String()))},
					TimeoutMs: 4500,
				}},
				QueryStrategy: appDNS.QueryStrategy_USE_IP4,
			}),
			serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{
				Networks:  []net.Network{net.Network_TCP},
				TargetTag: &router.RoutingRule_Tag{Tag: "selected"},
			}}}),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{Tag: "default-rejection", ProxySettings: serial.ToTypedMessage(&freedom.Config{Firewall: []*freedom.FirewallConfig{{Action: freedom.RuleAction_Block}}})},
			{Tag: "selected", ProxySettings: serial.ToTypedMessage(&freedom.Config{
				Firewall: []*freedom.FirewallConfig{{Action: freedom.RuleAction_Allow}},
			})},
		},
	})
	instance, err := core.New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer internet.InitSystemDialer(nil, nil)
	defer instance.Close()
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}

	conn, err := core.Dial(ctx, instance, net.DestinationFromAddr(origin.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var first [5]byte
	if _, err := io.ReadFull(conn, first[:]); err != nil || string(first[:]) != "ready" {
		t.Fatalf("server-first read on selected outbound: %q, %v", first, err)
	}
	if _, err := io.WriteString(conn, "echo"); err != nil {
		t.Fatal(err)
	}
	var echo [4]byte
	if _, err := io.ReadFull(conn, echo[:]); err != nil || string(echo[:]) != "echo" {
		t.Fatalf("real peer response: %q, %v", echo, err)
	}
	if err := <-exchanged; err != nil {
		t.Fatal(err)
	}

	missing := session.SetForcedOutboundTagToContext(ctx, "missing-native-proof-tag")
	rejected, err := core.Dial(missing, instance, net.DestinationFromAddr(origin.Addr()))
	if err != nil {
		t.Fatalf("opening failure must arrive through I/O: %v", err)
	}
	defer rejected.Close()
	if _, err := rejected.Read(echo[:]); err == nil {
		t.Fatalf("missing forced route: %v", err)
	}

	resolver := instance.GetFeature(dns.ClientType()).(dns.ContextClient)
	option := dns.IPOption{IPv4Enable: true}
	waiter, cancelWaiter := context.WithCancel(ctx)
	defer cancelWaiter()
	firstDone := make(chan error, 1)
	go func() {
		_, _, err := resolver.LookupIPContext(waiter, "shared-proof.invalid", option)
		firstDone <- err
	}()
	select {
	case <-queried:
	case <-ctx.Done():
		t.Fatal("DNS query did not reach the selected routed TCP nameserver")
	}
	secondDone := make(chan error, 1)
	go func() {
		ip, _, err := resolver.LookupIPContext(ctx, "shared-proof.invalid", option)
		if err == nil && (len(ip) != 1 || !ip[0].Equal(stdnet.IPv4(192, 0, 2, 34))) {
			err = errors.New("unexpected DNS answer")
		}
		secondDone <- err
	}()
	cancelWaiter()
	select {
	case err := <-firstDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("first DNS wait: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("first DNS wait did not cancel while the answer was held")
	}
	finishAnswer()
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("the live DNS lookup did not get an answer")
	}
	if queryCount.Load() != 1 {
		t.Fatalf("wire queries: %d, want one shared request", queryCount.Load())
	}
}

func TestCoreDialFixedPeerUDP(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	defer cancel()

	peers := make([]*stdnet.UDPConn, 2)
	for i := range peers {
		peer, err := stdnet.ListenUDP("udp4", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()
		if err := peer.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
			t.Fatal(err)
		}
		peers[i] = peer
	}
	instance, err := core.New(withDefaultApps(&core.Config{
		Outbound: []*core.OutboundHandlerConfig{{
			ProxySettings: serial.ToTypedMessage(&freedom.Config{
				Firewall: []*freedom.FirewallConfig{{Action: freedom.RuleAction_Allow}},
			}),
		}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer internet.InitSystemDialer(nil, nil)
	defer instance.Close()
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}

	roundtrip := func(peer *stdnet.UDPConn, payload string) *stdnet.UDPAddr {
		var buf [8]byte
		n, sender, err := peer.ReadFromUDP(buf[:])
		if err != nil || string(buf[:n]) != payload {
			t.Fatalf("peer received %q: %v", buf[:n], err)
		}
		if _, err := peer.WriteToUDP(buf[:n], sender); err != nil {
			t.Fatal(err)
		}
		return sender
	}
	fixed, err := core.Dial(ctx, instance, net.DestinationFromAddr(peers[0].LocalAddr()))
	if err != nil {
		t.Fatal(err)
	}
	defer fixed.Close()
	if _, err := io.WriteString(fixed, "fixed"); err != nil {
		t.Fatal(err)
	}
	roundtrip(peers[0], "fixed")
	var reply [8]byte
	n, err := fixed.Read(reply[:])
	if err != nil || string(reply[:n]) != "fixed" {
		t.Fatalf("fixed-peer UDP response: %q %v", reply[:n], err)
	}
	packet, err := core.DialUDP(ctx, instance)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	var firstSender string
	for i, peer := range peers {
		payload := []string{"first", "second"}[i]
		if _, err := packet.WriteTo([]byte(payload), peer.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		sender := roundtrip(peer, payload).String()
		if firstSender != "" && sender != firstSender {
			t.Fatalf("packet route opened another socket: %s, initial %s", sender, firstSender)
		}
		firstSender = sender
		n, src, err := packet.ReadFrom(reply[:])
		if err != nil || string(reply[:n]) != payload || src.String() != peer.LocalAddr().String() {
			t.Fatalf("multi-destination UDP response: %q from %v: %v", reply[:n], src, err)
		}
	}
	waiting := make(chan error, 1)
	go func() {
		var b [8]byte
		_, _, err := packet.ReadFrom(b[:])
		waiting <- err
	}()
	if err := packet.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-waiting:
		if err == nil {
			t.Fatal("ReadFrom did not report closure")
		}
	case <-ctx.Done():
		t.Fatal("ReadFrom stayed blocked after Close")
	}
}

func TestTaggedDialRejectionAndRoutedDoHReuse(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	defer cancel()
	server, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		peer, err := server.Accept()
		if err != nil {
			done <- err
			return
		}
		defer peer.Close()
		stop := context.AfterFunc(ctx, func() { peer.Close() })
		defer stop()
		(&http2.Server{}).ServeConn(peer, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, err := io.ReadAll(io.LimitReader(r.Body, 65535))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			query := new(wireDNS.Msg)
			if r.Method != http.MethodPost || r.URL.Path != "/dns-query" || query.Unpack(data) != nil || len(query.Question) != 1 {
				http.Error(w, "invalid local DNS request", http.StatusBadRequest)
				return
			}
			answer := new(wireDNS.Msg)
			answer.SetReply(query)
			answer.Answer = []wireDNS.RR{&wireDNS.A{Hdr: wireDNS.RR_Header{Name: query.Question[0].Name, Rrtype: wireDNS.TypeA, Class: wireDNS.ClassINET, Ttl: 30}, A: stdnet.IPv4(192, 0, 2, 79)}}
			packed, err := answer.Pack()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(packed)
		})})
		done <- nil
	}()

	config := withDefaultApps(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&appDNS.Config{NameServer: []*appDNS.NameServer{{
				Address:   &net.Endpoint{Address: net.NewIPOrDomain(net.DomainAddress("h2c://" + server.Addr().String() + "/dns-query"))},
				TimeoutMs: 4000,
			}}, QueryStrategy: appDNS.QueryStrategy_USE_IP4}),
			serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{
				Networks: []net.Network{net.Network_TCP}, TargetTag: &router.RoutingRule_Tag{Tag: "selected"},
			}}}),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{Tag: "reject", ProxySettings: serial.ToTypedMessage(&freedom.Config{Firewall: []*freedom.FirewallConfig{{Action: freedom.RuleAction_Block}}})},
			{Tag: "selected", ProxySettings: serial.ToTypedMessage(&freedom.Config{Firewall: []*freedom.FirewallConfig{{Action: freedom.RuleAction_Allow}}})},
		},
	})
	instance, err := core.New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer internet.InitSystemDialer(nil, nil)
	defer instance.Close()
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	resolver := instance.GetFeature(dns.ClientType()).(dns.ContextClient)
	ip, _, err := resolver.LookupIPContext(ctx, "h2c-proof.invalid", dns.IPOption{IPv4Enable: true})
	if err != nil || len(ip) != 1 || !ip[0].Equal(stdnet.IPv4(192, 0, 2, 79)) {
		t.Fatalf("routed DoH result: %v, %v", ip, err)
	}

	// The peer serves only one TCP connection. A fresh DNS question must reuse it.
	ip, _, err = resolver.LookupIPContext(ctx, "h2c-pooled.invalid", dns.IPOption{IPv4Enable: true})
	if err != nil || len(ip) != 1 || !ip[0].Equal(stdnet.IPv4(192, 0, 2, 79)) {
		t.Fatalf("reused DoH result: %v, %v", ip, err)
	}

	tagCtx := context.WithValue(ctx, core.XrayKey(1), instance)
	dispatcher := instance.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
	dialer, err := tagged.Dialer(tagCtx, dispatcher, net.DestinationFromAddr(server.Addr()), "absent-tagged-proof")
	if err != nil {
		t.Fatalf("missing tag must be reported by I/O: %v", err)
	}
	defer dialer.Close()
	if _, err := dialer.Read(make([]byte, 1)); err == nil {
		t.Fatalf("tagged routed open did not reject the unknown exact tag: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("DoH peer did not close")
	}
}

func TestCoreDialThroughLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	server, err := stdnet.ListenTCP("tcp4", &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	server.SetDeadline(time.Now().Add(4 * time.Second))
	unused, err := stdnet.ListenTCP("tcp4", &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer unused.Close()
	config := withDefaultApps(&core.Config{
		App: []*serial.TypedMessage{serial.ToTypedMessage(&router.Config{
			Rule: []*router.RoutingRule{{
				InboundTag: []string{"through-loopback"},
				TargetTag:  &router.RoutingRule_Tag{Tag: "socket"},
			}},
		})},
		Outbound: []*core.OutboundHandlerConfig{
			{Tag: "process-only", ProxySettings: serial.ToTypedMessage(&loopback.Config{InboundTag: "through-loopback"})},
			{Tag: "socket", ProxySettings: serial.ToTypedMessage(&freedom.Config{
				Firewall: []*freedom.FirewallConfig{{Action: freedom.RuleAction_Allow}},
			})},
			{Tag: "named-override", ProxySettings: serial.ToTypedMessage(&freedom.Config{
				DestinationOverride: &freedom.DestinationOverride{Server: &protocol.ServerEndpoint{
					Address: net.NewIPOrDomain(net.LocalHostIP),
					Port:    uint32(server.Addr().(*net.TCPAddr).Port),
				}},
				Firewall: []*freedom.FirewallConfig{{Action: freedom.RuleAction_Allow}},
			})},
		},
	})
	instance, err := core.New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer internet.InitSystemDialer(nil, nil)
	defer instance.Close()
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	conn, err := core.Dial(ctx, instance, net.DestinationFromAddr(server.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	exchange := func(conn net.Conn) {
		t.Helper()
		if _, err := io.WriteString(conn, "sent"); err != nil {
			t.Fatal(err)
		}
		peer, err := server.AcceptTCP()
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()
		peer.SetDeadline(time.Now().Add(time.Second))
		var message [4]byte
		if _, err := io.ReadFull(peer, message[:]); err != nil || string(message[:]) != "sent" {
			t.Fatalf("target received %q: %v", message, err)
		}
		if _, err := io.WriteString(peer, "back"); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(conn, message[:]); err != nil || string(message[:]) != "back" {
			t.Fatalf("application received %q: %v", message, err)
		}
	}
	exchange(conn)

	tagCtx := context.WithValue(ctx, core.XrayKey(1), instance)
	dispatcher := instance.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
	named, err := tagged.Dialer(tagCtx, dispatcher, net.DestinationFromAddr(unused.Addr()), "named-override")
	if err != nil {
		t.Fatal(err)
	}
	defer named.Close()
	exchange(named)

	draining, err := core.Dial(ctx, instance, net.DestinationFromAddr(server.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	defer draining.Close()
	if _, err := io.WriteString(draining, "tail"); err != nil {
		t.Fatal(err)
	}
	if err := draining.Close(); err != nil {
		t.Fatal(err)
	}
	lastPeer, err := server.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer lastPeer.Close()
	if err := lastPeer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var tail [4]byte
	if _, err := io.ReadFull(lastPeer, tail[:]); err != nil || string(tail[:]) != "tail" {
		t.Fatalf("reopened peer received %q after application closed: %v", tail, err)
	}
}
