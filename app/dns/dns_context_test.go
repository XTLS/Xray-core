package dns

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	featureDNS "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet"
)

type dnsContextTestKey struct{}

func dnsContextSystemResolver(t *testing.T) (<-chan context.Context, <-chan struct{}, func()) {
	t.Helper()
	started := make(chan context.Context, 8)
	canceled := make(chan struct{}, 8)
	release := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(release) }) }
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		select {
		case started <- ctx:
		default:
		}
		select {
		case <-ctx.Done():
			select {
			case canceled <- struct{}{}:
			default:
			}
			return nil, ctx.Err()
		case <-release:
			return nil, errors.New("test resolver released")
		}
	}}
	standard, common, controllers := net.DefaultResolver, xnet.DefaultResolver, internet.Controllers
	net.DefaultResolver, xnet.DefaultResolver, internet.Controllers = resolver, resolver, nil
	t.Cleanup(func() {
		stop()
		net.DefaultResolver, xnet.DefaultResolver, internet.Controllers = standard, common, controllers
	})
	return started, canceled, stop
}

func dnsContextScript(t *testing.T, server *DNS) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "context.lua")
	if err := os.WriteFile(path, []byte(`local server = require("xray.dns").Servers[1]
function HandleDNSQuery(domain, ipv4, ipv6, fake)
    return server:Query(domain, ipv4, ipv6, fake)
end`), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := newScriptEngine(path, server)
	if err != nil {
		t.Fatal(err)
	}
	server.script = engine
	t.Cleanup(engine.close)
}

func TestDNSLookupIPContextSystemCancellation(t *testing.T) {
	for _, mode := range []string{"serial", "parallel", "script"} {
		for _, cause := range []string{"cancel", "deadline"} {
			t.Run(mode+"/"+cause, func(t *testing.T) {
				started, canceled, _ := dnsContextSystemResolver(t)
				service, err := New(context.WithValue(t.Context(), dnsContextTestKey{}, "server"), &Config{EnableParallelQuery: mode == "parallel"})
				if err != nil {
					t.Fatal(err)
				}
				if mode == "script" {
					dnsContextScript(t, service)
				}
				request := context.WithValue(t.Context(), dnsContextTestKey{}, "request")
				var ctx context.Context
				var cancel context.CancelFunc
				if cause == "deadline" {
					ctx, cancel = context.WithTimeout(request, 500*time.Millisecond)
				} else {
					ctx, cancel = context.WithCancel(request)
				}
				defer cancel()
				done := make(chan error, 1)
				go func() {
					_, _, err := service.LookupIPContext(ctx, "blocked-context.xdns-test.invalid", featureDNS.IPOption{IPv4Enable: true})
					done <- err
				}()
				select {
				case received := <-started:
					if received.Value(dnsContextTestKey{}) != "request" {
						t.Error("request metadata did not reach system lookup")
					}
				case <-time.After(time.Second):
					t.Fatal("default localhost client did not enter system resolver")
				}
				if cause == "cancel" {
					cancel()
				}
				select {
				case err := <-done:
					if ctx.Err() == nil || !errors.Is(err, ctx.Err()) {
						t.Fatalf("lookup returned %v, context %v", err, ctx.Err())
					}
				case <-time.After(time.Second):
					t.Fatal("builtin DNS lookup ignored caller cancellation")
				}
				select {
				case <-canceled:
				case <-time.After(time.Second):
					t.Fatal("system DNS worker did not receive cancellation")
				}
				if service.ctx.Value(dnsContextTestKey{}) != "server" || service.ctx.Err() != nil {
					t.Fatal("lookup changed shared DNS context")
				}
			})
		}
	}
}

func TestDNSDefaultLocalLookupContextSuccess(t *testing.T) {
	service, err := New(t.Context(), &Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, lookup := range []func(string, featureDNS.IPOption) ([]xnet.IP, uint32, error){
		service.LookupIP,
		func(domain string, option featureDNS.IPOption) ([]xnet.IP, uint32, error) {
			return service.LookupIPContext(t.Context(), domain, option)
		},
	} {
		ips, _, err := lookup("127.0.0.1", featureDNS.IPOption{IPv4Enable: true})
		if err != nil || len(ips) != 1 || !ips[0].Equal(net.ParseIP("127.0.0.1")) {
			t.Fatalf("default local lookup = %v, %v", ips, err)
		}
	}
}

func TestDNSLookupIPContextAlreadyCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	service := &DNS{}
	if _, _, err := service.LookupIPContext(ctx, "", featureDNS.IPOption{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context returned %v", err)
	}
}

type dnsContextBlockingServer struct {
	cache    bool
	started  chan context.Context
	canceled chan struct{}
	release  chan struct{}
	once     sync.Once
}

func (*dnsContextBlockingServer) Name() string           { return "context-blocked" }
func (s *dnsContextBlockingServer) IsDisableCache() bool { return !s.cache }
func (s *dnsContextBlockingServer) QueryIP(ctx context.Context, domain string, option featureDNS.IPOption) ([]xnet.IP, uint32, error) {
	s.started <- ctx
	select {
	case <-ctx.Done():
		s.once.Do(func() { close(s.canceled) })
		return nil, 0, ctx.Err()
	case <-s.release:
		return []xnet.IP{net.ParseIP("127.0.0.1")}, 60, nil
	}
}

func TestDNSParallelContextCancelsEveryUncachedWorker(t *testing.T) {
	option := featureDNS.IPOption{IPv4Enable: true}
	hosts, err := NewStaticHosts(nil)
	if err != nil {
		t.Fatal(err)
	}
	servers := []*dnsContextBlockingServer{
		{started: make(chan context.Context, 1), canceled: make(chan struct{}), release: make(chan struct{})},
		{started: make(chan context.Context, 1), canceled: make(chan struct{}), release: make(chan struct{})},
	}
	for _, server := range servers {
		t.Cleanup(func() { close(server.release) })
	}
	service := &DNS{
		ctx: t.Context(), hosts: hosts, ipOption: &option, enableParallelQuery: true,
		clients: []*Client{{server: servers[0], ipOption: &option, timeoutMs: time.Minute}, {server: servers[1], ipOption: &option, timeoutMs: time.Minute}},
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, _, err := service.LookupIPContext(ctx, "workers.invalid", option); done <- err }()
	for _, server := range servers {
		select {
		case <-server.started:
		case <-time.After(time.Second):
			t.Fatal("parallel worker not started")
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("parallel wait did not cancel")
	}
	for _, server := range servers {
		select {
		case <-server.canceled:
		case <-time.After(time.Second):
			t.Fatal("uncached query worker still running")
		}
	}
}

func TestDNSScriptCloseCancelsContextLookup(t *testing.T) {
	option := featureDNS.IPOption{IPv4Enable: true}
	upstream := &dnsContextBlockingServer{started: make(chan context.Context, 1), canceled: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(upstream.release) }) })
	hosts, err := NewStaticHosts(nil)
	if err != nil {
		t.Fatal(err)
	}
	service := &DNS{ctx: t.Context(), hosts: hosts, ipOption: &option, clients: []*Client{{server: upstream, ipOption: &option, timeoutMs: time.Minute}}}
	dnsContextScript(t, service)
	done := make(chan error, 1)
	go func() { _, _, err := service.LookupIPContext(t.Context(), "script-close.invalid", option); done <- err }()
	select {
	case <-upstream.started:
	case <-time.After(time.Second):
		t.Fatal("script query did not start")
	}
	closed := make(chan struct{})
	go func() { _ = service.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		release.Do(func() { close(upstream.release) })
		t.Fatal("script Close did not cancel supplied-context query")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed script returned success")
		}
	case <-time.After(time.Second):
		t.Fatal("closed script query did not return")
	}
}

func TestDNSClientExplicitTimeoutStillApplies(t *testing.T) {
	option := featureDNS.IPOption{IPv4Enable: true}
	upstream := &dnsContextBlockingServer{started: make(chan context.Context, 1), canceled: make(chan struct{}), release: make(chan struct{})}
	client := &Client{server: upstream, ipOption: &option, timeoutMs: 25 * time.Millisecond}
	if _, _, err := client.QueryIP(t.Context(), "timeout.invalid", option); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("configured client timeout returned %v", err)
	}
}

func TestDNSLookupContextsAreIndependent(t *testing.T) {
	option := featureDNS.IPOption{IPv4Enable: true}
	upstream := &dnsContextBlockingServer{started: make(chan context.Context, 2), canceled: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	stop := func() { release.Do(func() { close(upstream.release) }) }
	defer stop()
	hosts, err := NewStaticHosts(nil)
	if err != nil {
		t.Fatal(err)
	}
	service := &DNS{ctx: context.WithValue(t.Context(), dnsContextTestKey{}, "server"), hosts: hosts, ipOption: &option, clients: []*Client{{server: upstream, ipOption: &option, timeoutMs: time.Minute}}}
	first, cancelFirst := context.WithCancel(context.WithValue(t.Context(), dnsContextTestKey{}, "first"))
	second, cancelSecond := context.WithCancel(context.WithValue(t.Context(), dnsContextTestKey{}, "second"))
	defer cancelFirst()
	defer cancelSecond()
	firstDone, secondDone := make(chan error, 1), make(chan error, 1)
	go func() { _, _, err := service.LookupIPContext(first, "first.invalid", option); firstDone <- err }()
	select {
	case received := <-upstream.started:
		if received.Value(dnsContextTestKey{}) != "first" {
			t.Error("first lookup lost request context")
		}
	case <-time.After(time.Second):
		t.Fatal("first lookup not started")
	}
	go func() { _, _, err := service.LookupIPContext(second, "second.invalid", option); secondDone <- err }()
	select {
	case received := <-upstream.started:
		if received.Value(dnsContextTestKey{}) != "second" {
			t.Error("second lookup lost request context")
		}
	case <-time.After(time.Second):
		t.Fatal("second lookup not started")
	}
	cancelFirst()
	select {
	case err := <-firstDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("first lookup did not cancel")
	}
	select {
	case err := <-secondDone:
		t.Fatalf("canceling first lookup affected second: %v", err)
	default:
	}
	stop()
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("second lookup did not complete")
	}
	if service.ctx.Value(dnsContextTestKey{}) != "server" || service.ctx.Err() != nil {
		t.Fatal("request context overwrote shared DNS state")
	}
}
