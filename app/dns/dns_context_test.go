package dns

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	featureDNS "github.com/xtls/xray-core/features/dns"
)

type dnsContextTestKey struct{}

type dnsContextTestWaiter struct {
	context.Context
	once sync.Once
	wait chan<- struct{}
}

func (w *dnsContextTestWaiter) Done() <-chan struct{} {
	w.once.Do(func() { w.wait <- struct{}{} })
	return w.Context.Done()
}

type dnsContextTestServer struct {
	cache   *CacheController
	wait    chan struct{}
	start   chan context.Context
	release chan struct{}
	queries atomic.Int32
}

func (s *dnsContextTestServer) Name() string                         { return s.cache.name }
func (s *dnsContextTestServer) IsDisableCache() bool                 { return s.cache.disableCache }
func (s *dnsContextTestServer) getCacheController() *CacheController { return s.cache }

func (s *dnsContextTestServer) QueryIP(ctx context.Context, domain string, option featureDNS.IPOption) ([]net.IP, uint32, error) {
	return queryIP(&dnsContextTestWaiter{Context: ctx, wait: s.wait}, s, domain, option)
}

func (s *dnsContextTestServer) sendQuery(ctx context.Context, _ chan<- error, fqdn string, _ featureDNS.IPOption) {
	s.queries.Add(1)
	select {
	case s.start <- ctx:
	case <-ctx.Done():
		return
	}
	select {
	case <-ctx.Done():
		return
	case <-s.release:
		s.cache.pub.Publish(fqdn+"4", &IPRecord{
			IP:     []net.IP{net.ParseIP("127.0.0.1")},
			Expire: time.Now().Add(time.Minute),
		})
	}
}

func TestLookupIPContextRetainsSharedQuery(t *testing.T) {
	for _, mode := range []string{"serial", "parallel", "script"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			service, stopService := context.WithTimeout(t.Context(), 8*time.Second)
			defer stopService()

			upstream := &dnsContextTestServer{
				cache:   NewCacheController("test", false, false, 0),
				wait:    make(chan struct{}, 2),
				start:   make(chan context.Context, 2),
				release: make(chan struct{}),
			}
			option := featureDNS.IPOption{IPv4Enable: true}
			hosts, err := NewStaticHosts(nil)
			if err != nil {
				t.Fatal(err)
			}
			server := &DNS{
				ctx:                 context.WithValue(service, dnsContextTestKey{}, "DNS service"),
				hosts:               hosts,
				ipOption:            &option,
				enableParallelQuery: mode == "parallel",
				clients: []*Client{{
					server:    upstream,
					ipOption:  &option,
					timeoutMs: 12 * time.Second,
					tag:       "dns-inbound",
				}},
			}
			if mode == "script" {
				path := filepath.Join(t.TempDir(), "resolve.lua")
				const script = `
local target = require("xray.dns").Servers[1]
function HandleDNSQuery(domain, ipv4, ipv6, fake)
    return target:Query(domain, ipv4, ipv6, fake)
end
`
				if err := os.WriteFile(path, []byte(script), 0600); err != nil {
					t.Fatal(err)
				}
				server.script, err = newScriptEngine(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := server.Start(); err != nil {
				t.Fatal(err)
			}
			defer server.Close()

			lookup := func(waiter context.Context) <-chan queryResult {
				done := make(chan queryResult, 1)
				go func() {
					ips, ttl, err := server.LookupIPContext(waiter, "shared.example", option)
					done <- queryResult{ips: ips, ttl: ttl, err: err}
				}()
				return done
			}
			waitForAdmission := func() {
				t.Helper()
				select {
				case <-upstream.wait:
				case <-ctx.Done():
					t.Fatal("query did not enter its cancelable wait")
				}
			}

			firstRoute, stopFirst := context.WithCancel(context.WithValue(ctx, dnsContextTestKey{}, "route caller"))
			defer stopFirst()
			first := lookup(firstRoute)
			var work context.Context
			select {
			case work = <-upstream.start:
			case <-ctx.Done():
				t.Fatal("DNS work did not start")
			}
			deadline, ok := work.Deadline()
			routeDeadline, _ := ctx.Deadline()
			if !ok || !deadline.After(routeDeadline) {
				t.Fatalf("shared work deadline %v must outlive the route deadline %v", deadline, routeDeadline)
			}
			serviceDeadline, _ := service.Deadline()
			if mode == "script" {
				if remaining := time.Until(deadline); remaining > scriptExecutionTimeout {
					t.Fatalf("shared work timeout %v exceeds the Lua deadline %v", remaining, scriptExecutionTimeout)
				}
			} else if !deadline.Equal(serviceDeadline) {
				t.Fatalf("shared work deadline %v, want DNS service deadline %v", deadline, serviceDeadline)
			}
			if got := work.Value(dnsContextTestKey{}); got != "DNS service" {
				t.Fatalf("DNS work metadata = %v", got)
			}
			if got := session.InboundFromContext(work); got == nil || got.Tag != "dns-inbound" {
				t.Fatalf("DNS work inbound metadata = %v", got)
			}
			waitForAdmission()
			second := lookup(ctx)
			waitForAdmission()

			stopFirst()
			select {
			case result := <-first:
				if len(result.ips) != 0 || !errors.Is(result.err, context.Canceled) {
					t.Fatalf("canceled lookup = %v, %v", result.ips, result.err)
				}
			case <-ctx.Done():
				t.Fatal("canceled lookup still waiting for DNS work")
			}
			if err := work.Err(); err != nil {
				t.Fatalf("canceling one waiter stopped shared work: %v", err)
			}
			close(upstream.release)

			select {
			case result := <-second:
				if result.err != nil || len(result.ips) != 1 || !result.ips[0].Equal(net.ParseIP("127.0.0.1")) {
					t.Fatalf("sibling lookup = %v, %v", result.ips, result.err)
				}
			case <-ctx.Done():
				t.Fatal("sibling lookup did not complete")
			}
			if count := upstream.queries.Load(); count != 1 {
				t.Fatalf("upstream ran %d queries for the shared key", count)
			}
		})
	}
}

func TestLookupIPContextDefaultLocalResolver(t *testing.T) {
	option := featureDNS.IPOption{IPv4Enable: true}
	hosts, err := NewStaticHosts(nil)
	if err != nil {
		t.Fatal(err)
	}
	server := &DNS{
		ctx:      t.Context(),
		hosts:    hosts,
		ipOption: &option,
		clients:  []*Client{NewLocalDNSClient(option)},
	}
	ips, _, err := server.LookupIPContext(t.Context(), "127.0.0.1", option)
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("default resolver lookup = %v, %v", ips, err)
	}
}

func TestLookupIPContextLocalResolverUsesRouteCancellation(t *testing.T) {
	started := make(chan struct{}, 1)
	originalResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			select {
			case started <- struct{}{}:
			default:
			}
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	defer func() { net.DefaultResolver = originalResolver }()

	option := featureDNS.IPOption{IPv4Enable: true}
	hosts, err := NewStaticHosts(nil)
	if err != nil {
		t.Fatal(err)
	}
	const configuredTimeout = 5 * time.Millisecond
	client := NewLocalDNSClient(option)
	client.timeoutMs = configuredTimeout
	server := &DNS{ctx: t.Context(), hosts: hosts, ipOption: &option, clients: []*Client{client}}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, _, err := server.LookupIPContext(ctx, "local-resolver-clock.test.", option)
		done <- err
	}()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("local lookup returned before the resolver waited: %v", err)
	case <-ctx.Done():
		t.Fatal("local resolver did not start")
	}
	select {
	case err := <-done:
		t.Fatalf("configured nameserver timeout stopped the local resolver: %v", err)
	case <-time.After(5 * configuredTimeout):
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("local lookup cancellation = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("route cancellation did not end the local resolver wait")
	}
}
