package dns

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	featureDNS "github.com/xtls/xray-core/features/dns"
	"golang.org/x/net/dns/dnsmessage"
)

type dnsContextCachedServer struct{ cache *CacheController }

func (s *dnsContextCachedServer) getCacheController() *CacheController { return s.cache }
func (*dnsContextCachedServer) sendQuery(ctx context.Context, errors chan<- error, domain string, option featureDNS.IPOption) {
}

type dnsFetchWaitContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *dnsFetchWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestDNSSharedFetchWaitCanCancel(t *testing.T) {
	cache := NewCacheController("context-test", false, false, 0)
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	stop := func() { releaseOnce.Do(func() { close(release) }) }
	defer stop()
	first := cache.requestGroup.DoChan("shared.invalid4", func() (any, error) {
		close(started)
		<-release
		return result{ips: []net.IP{net.ParseIP("127.0.0.1")}, ttl: 42}, nil
	})
	<-started
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	waitCtx := &dnsFetchWaitContext{Context: ctx, waiting: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		_, _, err := fetch(waitCtx, &dnsContextCachedServer{cache: cache}, "shared.invalid", featureDNS.IPOption{IPv4Enable: true})
		done <- err
	}()
	select {
	case <-waitCtx.waiting:
	case <-time.After(time.Second):
		t.Fatal("shared fetch wait has no cancellation path")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shared fetch ignored cancellation while waiting for another owner")
	}
	select {
	case <-first:
		t.Fatal("canceling another waiter terminated shared query owner")
	default:
	}
	successCtx := &dnsFetchWaitContext{Context: t.Context(), waiting: make(chan struct{})}
	success := make(chan result, 1)
	go func() {
		ips, ttl, err := fetch(successCtx, &dnsContextCachedServer{cache: cache}, "shared.invalid", featureDNS.IPOption{IPv4Enable: true})
		success <- result{ips: ips, ttl: ttl, error: err}
	}()
	select {
	case <-successCtx.waiting:
	case <-time.After(time.Second):
		t.Fatal("success waiter did not join shared fetch")
	}
	stop()
	select {
	case got := <-success:
		if got.error != nil || got.ttl != 42 || len(got.ips) != 1 || !got.ips[0].Equal(net.ParseIP("127.0.0.1")) {
			t.Fatalf("shared fetch lost result/TTL: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("shared success waiter did not return")
	}
}

type dnsCancelLeaderServer struct {
	cache      *CacheController
	queryCount atomic.Int32
	firstQuery chan struct{}
}

func (s *dnsCancelLeaderServer) getCacheController() *CacheController { return s.cache }
func (s *dnsCancelLeaderServer) sendQuery(ctx context.Context, _ chan<- error, domain string, _ featureDNS.IPOption) {
	if s.queryCount.Add(1) == 1 {
		close(s.firstQuery)
		<-ctx.Done()
		return
	}
	s.cache.pub.Publish(domain+"4", &IPRecord{
		IP:     []net.IP{net.ParseIP("192.0.2.17")},
		Expire: time.Now().Add(45 * time.Second),
		RCode:  0,
	})
}

func TestDNSSharedFetchLeaderCancellationDoesNotFailFollower(t *testing.T) {
	cache := NewCacheController("shared-cancel-test", false, false, 0)
	server := &dnsCancelLeaderServer{cache: cache, firstQuery: make(chan struct{})}
	option := featureDNS.IPOption{IPv4Enable: true}

	leaderCtx, cancelLeader := context.WithCancel(t.Context())
	defer cancelLeader()
	leaderDone := make(chan error, 1)
	go func() {
		_, _, err := queryIP(leaderCtx, server, "shared-cancel.invalid", option)
		leaderDone <- err
	}()
	select {
	case <-server.firstQuery:
	case <-time.After(time.Second):
		t.Fatal("leader did not start its DNS query")
	}

	followerCtx := &dnsFetchWaitContext{Context: t.Context(), waiting: make(chan struct{})}
	type fetchResult struct {
		ips []net.IP
		ttl uint32
		err error
	}
	followerDone := make(chan fetchResult, 1)
	go func() {
		ips, ttl, err := queryIP(followerCtx, server, "shared-cancel.invalid", option)
		followerDone <- fetchResult{ips: ips, ttl: ttl, err: err}
	}()
	select {
	case <-followerCtx.waiting:
	case <-time.After(time.Second):
		cancelLeader()
		t.Fatal("follower did not join the shared DNS query")
	}

	cancelLeader()
	select {
	case err := <-leaderDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("leader error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled leader did not return")
	}
	select {
	case got := <-followerDone:
		if got.err != nil || got.ttl != 45 || len(got.ips) != 1 || !got.ips[0].Equal(net.ParseIP("192.0.2.17")) {
			t.Fatalf("live follower did not receive the DNS result and TTL: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("live follower did not complete after leader cancellation")
	}
	if got := server.queryCount.Load(); got != 2 {
		t.Fatalf("backend query count = %d, want retry with follower context", got)
	}
}

type dnsPartialCacheCancelServer struct {
	cache       *CacheController
	queries     atomic.Int32
	firstQuery  chan struct{}
	secondQuery chan struct{}
	publish     chan struct{}
	published   chan struct{}
}

func (s *dnsPartialCacheCancelServer) getCacheController() *CacheController { return s.cache }
func (s *dnsPartialCacheCancelServer) sendQuery(ctx context.Context, _ chan<- error, domain string, _ featureDNS.IPOption) {
	if s.queries.Add(1) == 1 {
		s.firstQuery <- struct{}{}
		<-s.publish
		select {
		case <-ctx.Done():
			return
		default:
		}
		s.cache.updateRecord(&dnsRequest{reqType: dnsmessage.TypeA, domain: domain, start: time.Now()}, &IPRecord{
			IP:     []net.IP{net.ParseIP("192.0.2.23")},
			Expire: time.Now().Add(45 * time.Second),
			RCode:  dnsmessage.RCodeSuccess,
		})
		close(s.published)
		<-ctx.Done()
		return
	}
	select {
	case s.secondQuery <- struct{}{}:
	default:
	}
	<-ctx.Done()
}

func TestDNSSharedFetchUsesSuccessfulCacheAfterLeaderCancellation(t *testing.T) {
	cache := NewCacheController("shared-partial-cache-test", false, false, 0)
	t.Cleanup(func() { _ = cache.cacheCleanup.Close() })
	server := &dnsPartialCacheCancelServer{
		cache: cache, firstQuery: make(chan struct{}, 1), secondQuery: make(chan struct{}, 1),
		publish: make(chan struct{}), published: make(chan struct{}),
	}
	var publishOnce sync.Once
	publish := func() { publishOnce.Do(func() { close(server.publish) }) }
	defer publish()
	option := featureDNS.IPOption{IPv4Enable: true}

	leaderCtx, cancelLeader := context.WithCancel(t.Context())
	leaderDone := make(chan error, 1)
	leaderWorkerDone := make(chan struct{})
	go func() {
		defer close(leaderWorkerDone)
		_, _, err := queryIP(leaderCtx, server, "partial.invalid", option)
		leaderDone <- err
	}()
	defer func() {
		cancelLeader()
		select {
		case <-leaderWorkerDone:
		case <-time.After(time.Second):
			t.Error("leader worker did not stop")
		}
	}()
	select {
	case <-server.firstQuery:
	case <-time.After(time.Second):
		t.Fatal("leader did not start its DNS query")
	}

	followerBaseCtx, cancelFollower := context.WithCancel(t.Context())
	followerCtx := &dnsFetchWaitContext{Context: followerBaseCtx, waiting: make(chan struct{})}
	type fetchResult struct {
		ips []net.IP
		ttl uint32
		err error
	}
	followerDone := make(chan fetchResult, 1)
	followerWorkerDone := make(chan struct{})
	go func() {
		defer close(followerWorkerDone)
		ips, ttl, err := queryIP(followerCtx, server, "partial.invalid", option)
		followerDone <- fetchResult{ips: ips, ttl: ttl, err: err}
	}()
	defer func() {
		cancelFollower()
		select {
		case <-followerWorkerDone:
		case <-time.After(time.Second):
			t.Error("follower worker did not stop")
		}
	}()
	select {
	case <-followerCtx.waiting:
	case <-time.After(time.Second):
		cancelLeader()
		t.Fatal("follower did not join the shared DNS query")
	}
	publish()
	select {
	case <-server.published:
	case <-time.After(time.Second):
		t.Fatal("owner did not publish the successful A answer")
	}

	cancelLeader()
	select {
	case err := <-leaderDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("leader error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled leader did not return")
	}
	select {
	case got := <-followerDone:
		if got.err != nil || got.ttl == 0 || len(got.ips) != 1 || !got.ips[0].Equal(net.ParseIP("192.0.2.23")) {
			t.Fatalf("follower did not use cached A answer: %+v", got)
		}
	case <-server.secondQuery:
		t.Fatal("follower started another upstream query despite the successful cached A answer")
	case <-time.After(time.Second):
		t.Fatal("follower did not complete from the successful cache")
	}
}

type dnsCanceledFlightServer struct {
	cache   *CacheController
	queries atomic.Int32
	first   chan struct{}
	retry   chan struct{}
}

func (s *dnsCanceledFlightServer) getCacheController() *CacheController { return s.cache }
func (s *dnsCanceledFlightServer) sendQuery(ctx context.Context, _ chan<- error, _ string, _ featureDNS.IPOption) {
	if s.queries.Add(1) == 1 {
		close(s.first)
	} else {
		close(s.retry)
	}
	<-ctx.Done()
}

func TestDNSSharedFetchRejectsExpiredWrongFamilyAndDisabledCache(t *testing.T) {
	for _, mode := range []string{"expired", "wrong-family", "cache-disabled"} {
		t.Run(mode, func(t *testing.T) {
			cache := NewCacheController("shared-invalid-cache-test", false, false, 0)
			t.Cleanup(func() { _ = cache.cacheCleanup.Close() })
			if mode == "cache-disabled" {
				cache.disableCache = true
			}
			server := &dnsCanceledFlightServer{cache: cache, first: make(chan struct{}), retry: make(chan struct{})}
			option := featureDNS.IPOption{IPv4Enable: true}
			leaderCtx, cancelLeader := context.WithCancel(t.Context())
			leaderDone := make(chan error, 1)
			leaderWorkerDone := make(chan struct{})
			go func() {
				defer close(leaderWorkerDone)
				_, _, err := queryIP(leaderCtx, server, "invalid-cache.invalid", option)
				leaderDone <- err
			}()
			defer func() {
				cancelLeader()
				select {
				case <-leaderWorkerDone:
				case <-time.After(time.Second):
					t.Error("leader worker did not stop")
				}
			}()
			select {
			case <-server.first:
			case <-time.After(time.Second):
				t.Fatal("leader did not start its query")
			}

			followerBaseCtx, cancelFollower := context.WithCancel(t.Context())
			followerCtx := &dnsFetchWaitContext{Context: followerBaseCtx, waiting: make(chan struct{})}
			type fetchResult struct {
				ips []net.IP
				ttl uint32
				err error
			}
			followerResult := make(chan fetchResult, 1)
			followerWorkerDone := make(chan struct{})
			go func() {
				defer close(followerWorkerDone)
				ips, ttl, err := queryIP(followerCtx, server, "invalid-cache.invalid", option)
				followerResult <- fetchResult{ips: ips, ttl: ttl, err: err}
			}()
			defer func() {
				cancelFollower()
				select {
				case <-followerWorkerDone:
				case <-time.After(time.Second):
					t.Error("follower worker did not stop")
				}
			}()
			select {
			case <-followerCtx.waiting:
			case <-time.After(time.Second):
				t.Fatal("follower did not join the shared query")
			}

			ip := net.ParseIP("192.0.2.24")
			expire := time.Now().Add(45 * time.Second)
			reqType := dnsmessage.TypeA
			if mode == "expired" {
				expire = time.Now().Add(-time.Second)
			}
			if mode == "wrong-family" {
				reqType = dnsmessage.TypeAAAA
				ip = net.ParseIP("2001:db8::24")
			}
			if mode == "cache-disabled" {
				cache.Lock()
				cache.ips[Fqdn("invalid-cache.invalid")] = &record{A: &IPRecord{IP: []net.IP{ip}, Expire: expire, RCode: dnsmessage.RCodeSuccess}}
				cache.Unlock()
			} else {
				cache.updateRecord(&dnsRequest{reqType: reqType, domain: Fqdn("invalid-cache.invalid"), start: time.Now()}, &IPRecord{
					IP: []net.IP{ip}, Expire: expire, RCode: dnsmessage.RCodeSuccess,
				})
			}
			cancelLeader()
			select {
			case err := <-leaderDone:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("leader error = %v, want context.Canceled", err)
				}
			case <-time.After(time.Second):
				t.Fatal("canceled leader did not return")
			}
			select {
			case <-server.retry:
			case got := <-followerResult:
				t.Fatalf("follower accepted invalid %s cache: %+v", mode, got)
			case <-time.After(time.Second):
				t.Fatalf("follower neither retried nor returned for %s cache", mode)
			}
			cancelFollower()
			select {
			case got := <-followerResult:
				if !errors.Is(got.err, context.Canceled) {
					t.Fatalf("follower error = %v, want context.Canceled", got.err)
				}
			case <-time.After(time.Second):
				t.Fatal("canceled follower did not return")
			}
		})
	}
}

type dnsFailedQueryServer struct {
	cache      *CacheController
	queryCount atomic.Int32
}

func (s *dnsFailedQueryServer) getCacheController() *CacheController { return s.cache }
func (s *dnsFailedQueryServer) sendQuery(_ context.Context, _ chan<- error, domain string, _ featureDNS.IPOption) {
	s.queryCount.Add(1)
	s.cache.pub.Publish(domain+"4", &IPRecord{
		Expire: time.Now().Add(45 * time.Second),
		RCode:  dnsmessage.RCodeNameError,
	})
}

func TestDNSSharedFetchReturnsUpstreamFailureWithoutRetry(t *testing.T) {
	server := &dnsFailedQueryServer{
		cache: NewCacheController("shared-failure-test", false, false, 0),
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := queryIP(t.Context(), server, "failed.invalid", featureDNS.IPOption{IPv4Enable: true})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("negative DNS response returned no error")
		}
		if code := featureDNS.RCodeFromError(err); code != uint16(dnsmessage.RCodeNameError) {
			t.Fatalf("DNS response code = %d, want %d (NXDOMAIN)", code, dnsmessage.RCodeNameError)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream failure was retried instead of returned")
	}
	if got := server.queryCount.Load(); got != 1 {
		t.Fatalf("backend query count = %d, want 1", got)
	}
}
