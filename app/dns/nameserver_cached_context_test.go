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
