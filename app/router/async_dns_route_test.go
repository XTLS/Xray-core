package router_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

func asyncDNSRouteContext(domain string) *routing_session.Context {
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress(domain), 443),
	}})
	return routing_session.AsRoutingContext(ctx).(*routing_session.Context)
}

func TestAsyncDNSRouteMatcherDoesNotBlockOnCacheMiss(t *testing.T) {
	requested := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		_, _ = io.ReadAll(r.Body)
		requested <- struct{}{}
		<-release
		_, _ = w.Write([]byte(`{"state":"ready","route":"ru","ttlMillis":1000}`))
	}))
	defer server.Close()

	matcher, err := router.NewAsyncDNSRouteMatcher(&router.AsyncDnsRouteConfig{Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer matcher.Close()

	ctx := asyncDNSRouteContext("Bot.CloVPN.org.")
	started := time.Now()
	if matcher.Apply(ctx) {
		t.Fatal("cache miss must not match")
	}
	if elapsed := time.Since(started); elapsed > 20*time.Millisecond {
		t.Fatalf("cache miss blocked route selection for %s", elapsed)
	}

	select {
	case <-requested:
	case <-time.After(time.Second):
		t.Fatal("background classifier request was not sent")
	}
	close(release)

	deadline := time.Now().Add(time.Second)
	for !matcher.Apply(ctx) {
		if time.Now().After(deadline) {
			t.Fatal("ready RU classification did not populate L1 cache")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestAsyncDNSRouteMatcherCachesNonRUClassification(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"state":"ready","route":"other","ttlMillis":5000}`))
	}))
	defer server.Close()

	matcher, err := router.NewAsyncDNSRouteMatcher(&router.AsyncDnsRouteConfig{Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer matcher.Close()

	ctx := asyncDNSRouteContext("example.com")
	if matcher.Apply(ctx) {
		t.Fatal("cache miss must use fallback route")
	}

	deadline := time.Now().Add(time.Second)
	for calls.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("background classifier request was not sent")
		}
		time.Sleep(time.Millisecond)
	}

	for range 20 {
		if matcher.Apply(ctx) {
			t.Fatal("non-RU classification must use fallback route")
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("non-RU L1 cache did not suppress duplicate lookups: got %d requests", got)
	}
}
