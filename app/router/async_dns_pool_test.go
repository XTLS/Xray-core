package router

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const poolReady = `{"state":"ready","route":"ru","ttlMillis":5000,"generation":"same-fill"}`

func setAsyncDNSPoolPins(t *testing.T, endpoints []string) {
	t.Helper()
	encoded, err := json.Marshal(endpoints)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_ASYNC_DNS_OVERLAY_ENDPOINT", endpoints[0])
	t.Setenv(asyncDNSOverlayPoolEnv, string(encoded))
}

// Dial mapping is the test seam: production validation still rejects loopback
// pins, and the authorization boundary sees the exact private allowlist URL.
func newAsyncDNSPoolTestMatcher(t *testing.T, config *AsyncDnsRouteConfig, handlers ...http.HandlerFunc) *AsyncDNSRouteMatcher {
	t.Helper()
	addresses := make(map[string]string)
	endpoints := make([]string, len(handlers))
	for i, handler := range handlers {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer test-pool-token" || r.URL.Path != "/v1/classify" {
				t.Error("pool request lost exact endpoint or bearer")
			}
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
			handler(w, r)
		}))
		t.Cleanup(server.Close)
		address := fmt.Sprintf("100.64.0.%d:8090", i+10)
		addresses[address] = server.Listener.Addr().String()
		endpoints[i] = "http://" + address + "/v1/classify"
	}
	setAsyncDNSTestToken(t, "test-pool-token")
	setAsyncDNSPoolPins(t, endpoints)
	config.Endpoint = endpoints[0]
	m := newV2Matcher(t, config)
	transport := m.client.Transport.(*http.Transport)
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		mapped, ok := addresses[address]
		if !ok {
			return nil, errors.New("request outside test pool")
		}
		return (&net.Dialer{}).DialContext(ctx, network, mapped)
	}
	return m
}

func TestAsyncDNSPoolValidationFailsClosed(t *testing.T) {
	const first = "http://100.75.19.209:8090/v1/classify"
	const second = "http://100.64.0.10:8090/v1/classify"
	setAsyncDNSTestToken(t, "test-pool-token")
	t.Setenv("XRAY_ASYNC_DNS_OVERLAY_ENDPOINT", first)
	for _, raw := range []string{
		" ", "null", "[]", `{}`, `"not-an-array"`, `[`, `[null,null]`,
		`["` + first + `"]`, `["` + second + `","` + first + `"]`,
		`["` + first + `","` + first + `"]`,
		`["` + first + `","http://classifier.internal:8090/v1/classify"]`,
		`["` + first + `","http://8.8.8.8:8090/v1/classify"]`,
		`["` + first + `","http://127.0.0.1:8090/v1/classify"]`,
		`["` + first + `","http://100.64.0.10/v1/classify"]`,
		`["` + first + `","http://100.64.0.10:08090/v1/classify"]`,
		`["` + first + `","http://100.64.0.10:65536/v1/classify"]`,
		`["` + first + `","https://100.64.0.10:8090/v1/classify"]`,
		`["` + first + `","http://user@100.64.0.10:8090/v1/classify"]`,
		`["` + first + `","` + second + `?x=1"]`,
		`["` + first + `","` + second + `?"]`,
		`["` + first + `","` + second + `#fragment"]`,
		`["` + first + `","http://100.64.0.10:8090/v1/%63lassify"]`,
		`["` + first + `","http://100.64.0.10:8090/other"]`,
		`["` + first + `","` + second + `"] true`, strings.Repeat(" ", 4097),
	} {
		t.Run(fmt.Sprintf("invalid-%d", len(raw))+raw[:min(len(raw), 12)], func(t *testing.T) {
			t.Setenv(asyncDNSOverlayPoolEnv, raw)
			if m, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: first}); err == nil {
				m.Close()
				t.Fatal("accepted invalid operator pool")
			}
		})
	}
	t.Setenv(asyncDNSOverlayPoolEnv, "")
	legacy := newV2Matcher(t, &AsyncDnsRouteConfig{Endpoint: first})
	if legacy.pool != nil || legacy.transportIdentity != first {
		t.Fatal("empty plural env did not retain singular legacy transport")
	}
	endpoints := []string{first}
	for i := range 6 {
		endpoints = append(endpoints, fmt.Sprintf("http://100.64.0.%d:8090/v1/classify", i+10))
	}
	setAsyncDNSPoolPins(t, endpoints)
	if m, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: first}); err == nil {
		m.Close()
		t.Fatal("accepted more than six endpoints")
	}
	setAsyncDNSPoolPins(t, []string{first, second})
	m := newV2Matcher(t, &AsyncDnsRouteConfig{Endpoint: "https://other.invalid/v1/classify"})
	if m.pool != nil || m.transportIdentity != m.endpoint {
		t.Fatal("pool captured an unrelated owner rule")
	}
	t.Setenv("XRAY_ASYNC_DNS_BEARER_TOKEN_FILE", "")
	if m, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: first}); err == nil {
		m.Close()
		t.Fatal("pool accepted anonymous fallback")
	}
}

func TestAsyncDNSPoolFirstOperationFailoverAndPassiveCooldown(t *testing.T) {
	var failed, ready atomic.Int32
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150, RouteWaitMillis: 100},
		func(w http.ResponseWriter, r *http.Request) { failed.Add(1); w.WriteHeader(503) },
		func(w http.ResponseWriter, r *http.Request) { ready.Add(1); io.WriteString(w, poolReady) },
	)
	if !m.Apply(swrContext("first.example")) {
		t.Fatal("first backend error closed waiter before ready failover")
	}
	for _, domain := range []string{"second.example", "third.example"} {
		if _, err := m.fetch(domain); err != nil {
			t.Fatal(err)
		}
	}
	stats := m.Stats()
	if failed.Load() != 1 || ready.Load() != 3 || stats.PoolAttempts != 4 || stats.PoolFailovers != 1 || stats.PoolCooldownSkips == 0 || stats.PoolSize != 2 {
		t.Fatalf("passive cooldown/failover escaped bounds: failed=%d ready=%d stats=%+v", failed.Load(), ready.Load(), stats)
	}
}

func TestAsyncDNSPoolStopsFanoutOnAuthoritativeOrNonRetryableResult(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"pending", 200, `{"state":"pending","retryAfterMillis":5000}`},
		{"other", 200, `{"state":"ready","route":"other","ttlMillis":5000}`},
		{"stale", 200, `{"state":"stale","route":"ru","staleTtlMillis":5000}`},
		{"invalid-json", 200, `{`},
		{"invalid-shape", 200, `{"state":"broken"}`},
		{"unauthorized", 401, ``},
		{"forbidden", 403, ``},
		{"overload", 429, ``},
		{"redirect", 307, ``},
		{"bad-request", 400, ``},
		{"internal-error", 500, ``},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var other atomic.Int32
			m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150},
				func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Location", "http://8.8.8.8/leak")
					w.WriteHeader(tc.status)
					io.WriteString(w, tc.body)
				},
				func(w http.ResponseWriter, r *http.Request) { other.Add(1); io.WriteString(w, poolReady) },
			)
			_, _ = m.fetch("result.example")
			if other.Load() != 0 || m.Stats().PoolAttempts != 1 {
				t.Fatal("pool retried an authoritative/auth/overload/invalid response")
			}
		})
	}
	for _, status := range []int{502, 503, 504} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150},
				func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) },
				func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, poolReady) },
			)
			if response, err := m.fetch("retry.example"); err != nil || response.Route != "ru" || m.Stats().PoolAttempts != 2 {
				t.Fatalf("allowed HTTP failover failed: %v", err)
			}
		})
	}
}

func TestAsyncDNSPoolBackgroundTimeoutDoesNotBecomeRouteWait(t *testing.T) {
	var primary, secondary atomic.Int32
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150, RouteWaitMillis: 25, Workers: 1},
		func(w http.ResponseWriter, r *http.Request) { primary.Add(1); <-r.Context().Done() },
		func(w http.ResponseWriter, r *http.Request) { secondary.Add(1); io.WriteString(w, poolReady) },
	)
	if m.Apply(swrContext("late-pool.example")) {
		t.Fatal("25ms waiter waited for 75ms blackhole timeout")
	}
	if m.Stats().WaitTimeouts != 1 || secondary.Load() != 0 {
		t.Fatal("waiter exceeded its deadline or shortened background share")
	}
	eventuallyAsyncDNS(t, func() bool { return m.Stats().Entries == 1 })
	if !m.Apply(swrContext("late-pool.example")) || primary.Load() != 1 || secondary.Load() != 1 || m.Stats().Requests != 1 {
		t.Fatal("late shared failover did not populate L1 exactly once")
	}
}

func TestAsyncDNSPoolBoundsAttemptsAndTotalHTTPTimeout(t *testing.T) {
	var calls atomic.Int32
	handler := func(w http.ResponseWriter, r *http.Request) { calls.Add(1); <-r.Context().Done() }
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 90}, handler, handler, handler, handler, handler, handler)
	start := time.Now()
	if _, err := m.fetch("unavailable.example"); err == nil {
		t.Fatal("all-down pool succeeded")
	}
	if calls.Load() != 3 || m.Stats().PoolAttempts != 3 || time.Since(start) > 160*time.Millisecond {
		t.Fatalf("pool multiplied total timeout or attempted all six: calls=%d elapsed=%s", calls.Load(), time.Since(start))
	}
}

func TestAsyncDNSPoolCancellationStopsFailover(t *testing.T) {
	entered := make(chan struct{})
	var secondary atomic.Int32
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150},
		func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() },
		func(w http.ResponseWriter, r *http.Request) { secondary.Add(1); io.WriteString(w, poolReady) },
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := m.fetchContext(ctx, "cancel.example"); done <- err }()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) || secondary.Load() != 0 {
		t.Fatal("canceled shared operation continued through pool")
	}
}

func TestAsyncDNSPoolUsesSixEndpointsAndConcurrentStateIsBounded(t *testing.T) {
	counts := make([]atomic.Int32, 6)
	handlers := make([]http.HandlerFunc, 6)
	for i := range handlers {
		handlers[i] = func(w http.ResponseWriter, r *http.Request) { counts[i].Add(1); io.WriteString(w, poolReady) }
	}
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 600}, handlers...)
	var wg sync.WaitGroup
	for i := range 60 {
		wg.Go(func() {
			if _, err := m.fetch(fmt.Sprintf("parallel-%d.example", i)); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	for i := range counts {
		if counts[i].Load() != 10 {
			t.Fatalf("endpoint %d did not receive its bounded round-robin share: %d", i, counts[i].Load())
		}
	}
	if len(m.pool.states) != 6 || len(m.pool.allowed) != 6 || m.Stats().PoolAttempts != 60 {
		t.Fatal("pool health state or requests grew beyond its configured bounds")
	}
}

func TestAsyncDNSPoolWaitersShareOneLogicalFailoverOperation(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var failed, ready atomic.Int32
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150, RouteWaitMillis: 100, MaxWaiters: 32},
		func(w http.ResponseWriter, r *http.Request) { failed.Add(1); w.WriteHeader(503) },
		func(w http.ResponseWriter, r *http.Request) {
			if ready.Add(1) == 1 {
				close(entered)
			}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			io.WriteString(w, poolReady)
		},
	)
	var wg sync.WaitGroup
	wg.Go(func() {
		if !m.Apply(swrContext("shared-pool.example")) {
			t.Error("first waiter failed")
		}
	})
	<-entered
	for range 10 {
		wg.Go(func() {
			if !m.Apply(swrContext("shared-pool.example")) {
				t.Error("shared waiter failed")
			}
		})
	}
	eventuallyAsyncDNS(t, func() bool { return m.Stats().Waiters == 11 })
	close(release)
	wg.Wait()
	if failed.Load() != 1 || ready.Load() != 1 || m.Stats().Requests != 1 || m.Stats().PoolAttempts != 2 {
		t.Fatal("waiters multiplied logical failover operation")
	}
}

func TestAsyncDNSPoolBearerNeverUsesProxyRedirectOrUnpinnedEndpoint(t *testing.T) {
	var leaked atomic.Int32
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	defer outside.Close()
	t.Setenv("HTTP_PROXY", outside.URL)
	t.Setenv("HTTPS_PROXY", outside.URL)
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{},
		func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, outside.URL, 307) },
		func(w http.ResponseWriter, r *http.Request) { t.Error("redirect caused pool retry") },
	)
	if m.client.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("pool inherited an environment proxy")
	}
	if _, err := m.fetch("redirect.example"); err == nil {
		t.Fatal("pool followed redirect")
	}
	for _, endpoint := range []string{outside.URL, "https://unrelated.invalid/v1/classify", "http://100.64.0.10:8090/other", "http://100.64.0.10:8090/v1/classify?x=1"} {
		if _, err := m.fetchEndpoint(context.Background(), endpoint, "guard.example"); err == nil {
			t.Fatal("bearer escaped exact pool allowlist")
		}
	}
	if leaked.Load() != 0 {
		t.Fatal("pool token escaped through proxy or redirect")
	}
}

func TestAsyncDNSPoolSnapshotIdentityAndReloadSemantics(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("snapshot requires POSIX permissions")
	}
	endpoints := []string{"http://100.64.0.10:8090/v1/classify", "http://100.64.0.11:8090/v1/classify"}
	setAsyncDNSTestToken(t, "test-pool-token")
	setAsyncDNSPoolPins(t, endpoints)
	path := filepath.Join(t.TempDir(), "cache", "l1.json")
	config := &AsyncDnsRouteConfig{Endpoint: endpoints[0], SnapshotPath: path, SnapshotCompatibilityId: "process:shared-semantic-namespace"}
	m := newV2Matcher(t, config)
	selfDone := make(chan struct{})
	go func() { m.pool.inherit(m.pool); close(selfDone) }()
	select {
	case <-selfDone:
	case <-time.After(time.Second):
		t.Fatal("pool self-inheritance deadlocked")
	}
	now := time.Now()
	m.mu.Lock()
	m.acceptResponse("saved.example", &asyncDNSClassifierResponse{State: "ready", Route: "ru", TTLMillis: 5000, Generation: "same-fill"}, now, now)
	old := m.cache["saved.example"]
	m.mu.Unlock()
	m.pool.record(endpoints[0], true, now)
	same := newV2Matcher(t, &AsyncDnsRouteConfig{Endpoint: endpoints[0]})
	same.inheritState(m)
	if same.Stats().InheritedEntries != 1 || !same.pool.states[0].cooldownUntil.Equal(m.pool.states[0].cooldownUntil) {
		t.Fatal("compatible reload lost warm entries or passive cooldown")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	setAsyncDNSPoolPins(t, []string{endpoints[1], endpoints[0]})
	config.Endpoint = endpoints[1]
	reordered := newV2Matcher(t, config)
	reordered.mu.Lock()
	restored := reordered.cache["saved.example"]
	reordered.mu.Unlock()
	if reordered.Stats().RestoredEntries != 1 || !old.freshUntil.Equal(restored.freshUntil) || !old.hardUntil.Equal(restored.hardUntil) || !old.serverHardUntil.Equal(restored.serverHardUntil) {
		t.Fatal("pool reorder lost snapshot or renewed its absolute TTL")
	}
	config.SnapshotCompatibilityId = "process:different-semantic-namespace"
	wrongNamespace := newV2Matcher(t, config)
	if wrongNamespace.Stats().RestoredEntries != 0 {
		t.Fatal("snapshot accepted incompatible semantic namespace")
	}
	setAsyncDNSPoolPins(t, []string{endpoints[0], "http://100.64.0.12:8090/v1/classify"})
	config.Endpoint, config.SnapshotCompatibilityId = endpoints[0], "process:shared-semantic-namespace"
	wrongPool := newV2Matcher(t, config)
	wrongPool.inheritState(same)
	if wrongPool.Stats().RestoredEntries != 0 || wrongPool.Stats().InheritedEntries != 0 {
		t.Fatal("pool membership change accepted persistent or inherited classifications")
	}
}
