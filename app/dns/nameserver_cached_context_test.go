package dns

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	featureDNS "github.com/xtls/xray-core/features/dns"
)

type dnsContextCachedServer struct { cache *CacheController }
func (s *dnsContextCachedServer) getCacheController() *CacheController { return s.cache }
func (*dnsContextCachedServer) sendQuery(ctx context.Context, errors chan<- error, domain string, option featureDNS.IPOption) {}

type dnsFetchWaitContext struct { context.Context; waiting chan struct{}; once sync.Once }
func (c *dnsFetchWaitContext) Done() <-chan struct{} { c.once.Do(func() { close(c.waiting) }); return c.Context.Done() }

func TestDNSSharedFetchWaitCanCancel(t *testing.T) {
	cache := NewCacheController("context-test", false, false, 0)
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	stop := func() { releaseOnce.Do(func() { close(release) }) }
	defer stop()
	first := cache.requestGroup.DoChan("shared.invalid4", func()(any,error) {
		close(started)
		<-release
		return result{ips: []net.IP{net.ParseIP("127.0.0.1")}, ttl: 42}, nil
	})
	<-started
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	waitCtx := &dnsFetchWaitContext{Context: ctx, waiting: make(chan struct{})}
	done := make(chan error, 1)
	go func() { _, _, err := fetch(waitCtx, &dnsContextCachedServer{cache: cache}, "shared.invalid", featureDNS.IPOption{IPv4Enable: true}); done <- err }()
	select { case <-waitCtx.waiting: case <-time.After(time.Second): t.Fatal("shared fetch wait has no cancellation path") }
	cancel()
	select { case err := <-done: if !errors.Is(err, context.Canceled) { t.Fatal(err) }; case <-time.After(time.Second): t.Fatal("shared fetch ignored cancellation while waiting for another owner") }
	select { case <-first: t.Fatal("canceling another waiter terminated shared query owner"); default: }
	successCtx := &dnsFetchWaitContext{Context: t.Context(), waiting: make(chan struct{})}
	success := make(chan result, 1)
	go func() { ips, ttl, err := fetch(successCtx, &dnsContextCachedServer{cache: cache}, "shared.invalid", featureDNS.IPOption{IPv4Enable: true}); success <- result{ips: ips, ttl: ttl, error: err} }()
	select { case <-successCtx.waiting: case <-time.After(time.Second): t.Fatal("success waiter did not join shared fetch") }
	stop()
	select { case got := <-success: if got.error != nil || got.ttl != 42 || len(got.ips) != 1 || !got.ips[0].Equal(net.ParseIP("127.0.0.1")) { t.Fatalf("shared fetch lost result/TTL: %+v", got) }; case <-time.After(time.Second): t.Fatal("shared success waiter did not return") }
}
