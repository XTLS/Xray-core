package router

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

func newV2Matcher(t *testing.T, config *AsyncDnsRouteConfig) *AsyncDNSRouteMatcher {
	t.Helper()
	m, err := NewAsyncDNSRouteMatcher(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func TestAsyncDNSWaitUsesReadyFirstConnectionAndCachesOther(t *testing.T) {
	for _, route := range []string{"ru", "other"} {
		t.Run(route, func(t *testing.T) {
			var calls atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				fmt.Fprintf(w, `{"state":"ready","route":%q,"ttlMillis":5000,"generation":"one"}`, route)
			}))
			defer s.Close()
			m := newV2Matcher(t, &AsyncDnsRouteConfig{Endpoint: s.URL, RouteWaitMillis: 100})
			if m.Apply(swrContext("first.example")) != (route == "ru") {
				t.Fatal("first ready classification did not decide current route")
			}
			for range 20 {
				if m.Apply(swrContext("first.example")) != (route == "ru") {
					t.Fatal("cached route differs")
				}
			}
			if calls.Load() != 1 {
				t.Fatalf("duplicate ready lookup: %d", calls.Load())
			}
		})
	}
}

func TestAsyncDNSWaitPendingDoesNotWaitForRetry(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"state":"pending","retryAfterMillis":5000}`)
	}))
	defer s.Close()
	m := newV2Matcher(t, &AsyncDnsRouteConfig{Endpoint: s.URL, RouteWaitMillis: 100})
	start := time.Now()
	if m.Apply(swrContext("pending.example")) {
		t.Fatal("pending matched")
	}
	if time.Since(start) >= 80*time.Millisecond {
		t.Fatal("waiter waited for DNS/retry instead of first pending response")
	}
	if m.Stats().Requests != 1 {
		t.Fatal("pending waiter generated extra RPC")
	}
}

func TestAsyncDNSWaitersShareRPCAndCancellation(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		io.WriteString(w, `{"state":"ready","route":"ru","ttlMillis":5000}`)
	}))
	defer s.Close()
	m := newV2Matcher(t, &AsyncDnsRouteConfig{Endpoint: s.URL, RouteWaitMillis: 100, MaxWaiters: 64})
	ctx, cancel := context.WithCancel(context.Background())
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: net.TCPDestination(net.DomainAddress("shared.example"), 443)}})
	canceled := make(chan bool, 1)
	go func() { canceled <- m.Apply(routing_session.AsRoutingContext(ctx)) }()
	<-entered
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if !m.Apply(swrContext("shared.example")) {
				t.Error("healthy shared waiter failed")
			}
		})
	}
	eventuallyAsyncDNS(t, func() bool { return m.Stats().Waiters == 21 })
	cancel()
	select {
	case result := <-canceled:
		if result {
			t.Fatal("canceled waiter matched")
		}
	case <-time.After(50 * time.Millisecond):
		t.Fatal("cancel did not stop waiter")
	}
	close(release)
	wg.Wait()
	if calls.Load() != 1 || !m.Apply(swrContext("shared.example")) {
		t.Fatal("waiter cancellation canceled common RPC or duplicated it")
	}
}

func TestAsyncDNSWaitCapAndLateResponse(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		io.WriteString(w, `{"state":"ready","route":"ru","ttlMillis":5000}`)
	}))
	defer s.Close()
	m := newV2Matcher(t, &AsyncDnsRouteConfig{Endpoint: s.URL, RouteWaitMillis: 25, MaxWaiters: 1})
	result := make(chan bool, 1)
	go func() { result <- m.Apply(swrContext("late.example")) }()
	<-entered
	start := time.Now()
	if m.Apply(swrContext("late.example")) {
		t.Fatal("overloaded waiter matched")
	}
	if time.Since(start) > 15*time.Millisecond {
		t.Fatal("overloaded waiter queued")
	}
	if <-result {
		t.Fatal("timeout rerouted connection")
	}
	close(release)
	eventuallyAsyncDNS(t, func() bool { return m.Stats().Entries == 1 })
	if !m.Apply(swrContext("late.example")) || m.Stats().Requests != 1 || m.Stats().WaitDrops != 1 {
		t.Fatal("late response failed to warm L1 without duplicate RPC")
	}
}

func TestAsyncDNSRouteBudgetSharedByRules(t *testing.T) {
	pending := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(18 * time.Millisecond)
		io.WriteString(w, `{"state":"pending","retryAfterMillis":5000}`)
	}))
	defer pending.Close()
	ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(18 * time.Millisecond)
		io.WriteString(w, `{"state":"ready","route":"ru","ttlMillis":5000}`)
	}))
	defer ready.Close()
	r := new(Router)
	config := &Config{Rule: []*RoutingRule{
		{RuleTag: "first", TargetTag: &RoutingRule_Tag{Tag: "ru1"}, AsyncDnsRoute: &AsyncDnsRouteConfig{Endpoint: pending.URL, RouteWaitMillis: 25}},
		{RuleTag: "second", TargetTag: &RoutingRule_Tag{Tag: "ru2"}, AsyncDnsRoute: &AsyncDnsRouteConfig{Endpoint: ready.URL, RouteWaitMillis: 25}},
		{RuleTag: "fallback", TargetTag: &RoutingRule_Tag{Tag: "default"}, Networks: []net.Network{net.Network_TCP}},
	}}
	if err := r.Init(context.Background(), config, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	route, err := r.PickRoute(swrContext("aggregate.example"))
	if err != nil {
		t.Fatal(err)
	}
	if route.GetOutboundTag() != "default" {
		t.Fatal("each rule added its own budget; second ready should arrive after aggregate deadline")
	}
	eventuallyAsyncDNS(t, func() bool { return asyncDNSCondition((*r.rules.Load())[1].Condition).Stats().Entries == 1 })
	route, err = r.PickRoute(swrContext("aggregate.example"))
	if err != nil || route.GetOutboundTag() != "ru2" {
		t.Fatal("late answer not available to next connection")
	}
}

func TestAsyncDNSLRUPromotesUsersOnly(t *testing.T) {
	m := projectionMatcher(0)
	m.cacheCapacity = 3
	now := time.Now()
	response := &asyncDNSClassifierResponse{State: "ready", Route: "ru", TTLMillis: 50000, Generation: "first"}
	for _, domain := range []string{"hot", "cold", "latest"} {
		m.acceptResponse(domain, response, now, now)
	}
	m.lookup("hot", now.Add(time.Millisecond))
	m.acceptResponse("cold", response, now, now.Add(2*time.Millisecond)) // background must not touch LRU
	m.acceptResponse("new", response, now, now.Add(3*time.Millisecond))
	if _, ok := m.cache["cold"]; ok {
		t.Fatal("background reread promoted cold key")
	}
	if _, ok := m.cache["hot"]; !ok {
		t.Fatal("user hot key evicted")
	}
	if m.lru.Len() != 3 || len(m.lruIndex) != 3 || m.Stats().Evictions != 1 {
		t.Fatal("LRU indexes or bounds differ")
	}
}

func TestAsyncDNSSnapshotRestartPreservesDeadlinesAndLRU(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache", "l1.json")
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"state":"ready","route":"ru","ttlMillis":5000,"staleTtlMillis":10000,"generation":"same-fill"}`)
	}))
	defer s.Close()
	config := &AsyncDnsRouteConfig{Endpoint: s.URL, RouteWaitMillis: 100, StaleGraceMillis: 1000, SnapshotPath: path, SnapshotCompatibilityId: "process:resolver:geoip:v1"}
	m := newV2Matcher(t, config)
	if !m.Apply(swrContext("saved.example")) {
		t.Fatal("initial route")
	}
	m.mu.Lock()
	old := m.cache["saved.example"]
	m.mu.Unlock()
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatal("snapshot not private")
	}
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil || dir.Mode().Perm() != 0o700 {
		t.Fatal("directory not private")
	}
	next := newV2Matcher(t, config)
	next.mu.Lock()
	restored := next.cache["saved.example"]
	next.mu.Unlock()
	if !old.hardUntil.Equal(restored.hardUntil) || !old.freshUntil.Equal(restored.freshUntil) || !old.serverHardUntil.Equal(restored.serverHardUntil) || old.generation != restored.generation {
		t.Fatal("restart reset cache leases")
	}
	if next.Stats().RestoredEntries != 1 || !next.Apply(swrContext("saved.example")) || next.Stats().Requests != 0 {
		t.Fatal("restart needs new network request")
	}
}

func TestAsyncDNSSnapshotRejectedContextCorruptionClockAndExpiry(t *testing.T) {
	now := time.Now()
	p := asyncDNSSnapshotPayload{Version: asyncDNSSnapshotVersion, Identity: "context", SavedAt: now, Entries: []asyncDNSSnapshotEntry{{Domain: "saved.example", RouteRU: true, FreshUntil: now.Add(time.Second), HardUntil: now.Add(2 * time.Second), ServerHardUntil: now.Add(3 * time.Second), LastUsed: now, RefreshAt: now.Add(time.Second)}}}
	data, err := encodeAsyncDNSSnapshot(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeAsyncDNSSnapshot(data, "other", now, 4096, time.Minute); err == nil {
		t.Fatal("wrong identity accepted")
	}
	if _, err = decodeAsyncDNSSnapshot(data, "context", now.Add(-time.Second), 4096, time.Minute); err == nil {
		t.Fatal("clock rollback accepted")
	}
	if entries, err := decodeAsyncDNSSnapshot(data, "context", now.Add(2*time.Second), 4096, time.Minute); err != nil || len(entries) != 0 {
		t.Fatal("hard expired snapshot restored")
	}
	data[len(data)/2] ^= 1
	if _, err = decodeAsyncDNSSnapshot(data, "context", now, 4096, time.Minute); err == nil {
		t.Fatal("corrupted snapshot accepted")
	}
}

func TestAsyncDNSSnapshotFailureAndDuplicatePathsDoNotStopRouting(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "blocked")
	if err := os.WriteFile(parent, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := &AsyncDnsRouteConfig{Endpoint: "https://example.invalid", SnapshotPath: filepath.Join(parent, "l1.json"), SnapshotCompatibilityId: "context"}
	m := newV2Matcher(t, config)
	now := time.Now()
	m.mu.Lock()
	m.acceptResponse("ready.example", &asyncDNSClassifierResponse{State: "ready", Route: "ru", TTLMillis: 5000}, now, now)
	m.mu.Unlock()
	m.persistSnapshot()
	if m.Stats().SnapshotErrors == 0 || !m.Apply(swrContext("ready.example")) {
		t.Fatal("bad disk affected in-memory routing")
	}
	r := new(Router)
	duplicate := &Config{Rule: []*RoutingRule{{TargetTag: &RoutingRule_Tag{Tag: "a"}, AsyncDnsRoute: config}, {TargetTag: &RoutingRule_Tag{Tag: "b"}, AsyncDnsRoute: config}}}
	if err := r.Init(context.Background(), duplicate, nil, nil, nil); err == nil {
		r.Close()
		t.Fatal("shared snapshot path accepted")
	}
}

func TestAsyncDNSSnapshotBounds(t *testing.T) {
	now := time.Now()
	p := asyncDNSSnapshotPayload{Version: asyncDNSSnapshotVersion, Identity: "context", SavedAt: now}
	for i := 0; i < 4096; i++ {
		p.Entries = append(p.Entries, asyncDNSSnapshotEntry{Domain: fmt.Sprintf("%d.example", i), FreshUntil: now.Add(time.Second), HardUntil: now.Add(time.Second), ServerHardUntil: now.Add(time.Second), RefreshAt: now, LastUsed: now})
	}
	data, err := encodeAsyncDNSSnapshot(p)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := decodeAsyncDNSSnapshot(data, "context", now, 7, time.Minute)
	if err != nil || len(entries) != 7 {
		t.Fatal("restore capacity not enforced")
	}
	p.Entries = append(p.Entries, p.Entries[0])
	data, err = encodeAsyncDNSSnapshot(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeAsyncDNSSnapshot(data, "context", now, 4096, time.Minute); err == nil {
		t.Fatal("oversized entry set accepted")
	}
}

func TestAsyncDNSCloseReleasesWaitingConnection(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-release }))
	defer s.Close()
	m := newV2Matcher(t, &AsyncDnsRouteConfig{Endpoint: s.URL, RouteWaitMillis: 100})
	result := make(chan bool, 1)
	go func() { result <- m.Apply(swrContext("close.example")) }()
	<-entered
	start := time.Now()
	m.Close()
	close(release)
	if time.Since(start) > time.Second {
		t.Fatal("close exceeded cancellation budget")
	}
	select {
	case matched := <-result:
		if matched {
			t.Fatal("close rerouted waiter")
		}
	case <-time.After(time.Second):
		t.Fatal("waiter not released")
	}
}

func TestAsyncDNSClassifierCooldownCoversUniqueDomains(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer s.Close()
	m := newV2Matcher(t, &AsyncDnsRouteConfig{Endpoint: s.URL, RouteWaitMillis: 100, Workers: 1})
	for i := 0; i < 3; i++ {
		m.Apply(swrContext(fmt.Sprintf("failed-%d.example", i)))
	}
	for i := 0; i < 30; i++ {
		m.Apply(swrContext(fmt.Sprintf("suppressed-%d.example", i)))
	}
	if calls.Load() != 3 {
		t.Fatalf("unique-domain stream bypassed cooldown: %d RPCs", calls.Load())
	}
	now := time.Now()
	m.mu.Lock()
	m.acceptResponse("healthy.example", &asyncDNSClassifierResponse{State: "ready", Route: "ru", TTLMillis: 5000}, now, now)
	m.mu.Unlock()
	if !m.Apply(swrContext("healthy.example")) {
		t.Fatal("cooldown disabled cached route")
	}
}

func BenchmarkAsyncDNSLRUHit4096(b *testing.B) {
	m := projectionMatcher(0)
	m.cacheCapacity = 4096
	now := time.Now()
	reply := &asyncDNSClassifierResponse{State: "ready", Route: "ru", TTLMillis: 3600000}
	for i := 0; i < 4096; i++ {
		m.acceptResponse(fmt.Sprintf("%d.example", i), reply, now, now)
	}
	ctx := swrContext("0.example")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		m.Apply(ctx)
	}
}
