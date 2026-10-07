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
	if failed.Load() != 1 || ready.Load() != 3 || stats.PoolAttempts != 4 || stats.PoolFailovers != 1 || stats.PoolCooldownSkips != 0 || stats.PoolSize != 2 {
		t.Fatalf("passive cooldown/failover escaped bounds: failed=%d ready=%d stats=%+v", failed.Load(), ready.Load(), stats)
	}
}

func TestAsyncDNSPoolFirstThreeFastTransportFailuresReachFourthMember(t *testing.T) {
	var ready, unexpected atomic.Int32
	unused := func(w http.ResponseWriter, r *http.Request) { unexpected.Add(1) }
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150},
		unused, unused, unused,
		func(w http.ResponseWriter, r *http.Request) { ready.Add(1); io.WriteString(w, poolReady) },
		unused, unused,
	)
	transport := m.client.Transport.(*http.Transport)
	dial := transport.DialContext
	var failed atomic.Int32
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "100.64.0.10:8090" || address == "100.64.0.11:8090" || address == "100.64.0.12:8090" {
			failed.Add(1)
			return nil, errors.New("connection refused")
		}
		return dial(ctx, network, address)
	}
	response, err := m.fetch("three-primaries-down.example")
	stats := m.Stats()
	if err != nil || response == nil || response.Route != "ru" || failed.Load() != 3 || ready.Load() != 1 || unexpected.Load() != 0 || stats.PoolAttempts != 4 || stats.PoolFailovers != 3 {
		t.Fatalf("first operation did not reach the healthy reserve: response=%+v err=%v failed=%d ready=%d unexpected=%d stats=%+v", response, err, failed.Load(), ready.Load(), unexpected.Load(), stats)
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
		t.Fatal("25ms waiter waited for 150ms background timeout")
	}
	if m.Stats().WaitTimeouts != 1 || secondary.Load() != 0 {
		t.Fatal("waiter exceeded its deadline or shortened background share")
	}
	eventuallyAsyncDNS(t, func() bool { return m.Stats().Entries == 1 })
	if !m.Apply(swrContext("late-pool.example")) || primary.Load() != 1 || secondary.Load() != 1 || m.Stats().Requests != 1 || m.Stats().Errors != 0 {
		t.Fatal("bounded background hedge did not recover L1 in one operation")
	}
}

func TestAsyncDNSPoolBoundsAttemptsAndTotalHTTPTimeout(t *testing.T) {
	t.Run("six-immediate-retryable-errors", func(t *testing.T) {
		var calls atomic.Int32
		handler := func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(503) }
		m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, handler, handler, handler, handler, handler, handler)
		if _, err := m.fetch("all-six-failed.example"); err == nil {
			t.Fatal("all-down pool succeeded")
		}
		if calls.Load() != 6 || m.Stats().PoolAttempts != 6 || m.Stats().PoolFailovers != 5 {
			t.Fatalf("operation did not reach exactly the configured six members: calls=%d stats=%+v", calls.Load(), m.Stats())
		}
	})
	for _, timeout := range []uint32{150, 200} {
		t.Run(fmt.Sprint(timeout), func(t *testing.T) {
			var calls atomic.Int32
			handler := func(w http.ResponseWriter, r *http.Request) { calls.Add(1); <-r.Context().Done() }
			m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: timeout}, handler, handler, handler, handler, handler, handler)
			start := time.Now()
			if _, err := m.fetch("unavailable.example"); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("all-down pool did not expire its parent: %v", err)
			}
			elapsed := time.Since(start)
			stats := m.Stats()
			// Six silent attempts share one deadline; no slot is created by
			// canceling a live attempt. Fast failures also reach six members.
			if calls.Load() != 6 || stats.PoolAttempts != 6 || stats.PoolFailovers != 5 || elapsed < time.Duration(timeout)*time.Millisecond-20*time.Millisecond || elapsed > time.Duration(timeout)*time.Millisecond+80*time.Millisecond {
				t.Fatalf("pool multiplied the shared timeout or escaped attempt bounds: calls=%d elapsed=%s stats=%+v", calls.Load(), elapsed, stats)
			}
			if m.pool.states[0].failures != 1 || !time.Now().Before(m.pool.states[0].cooldownUntil) {
				t.Fatal("all-blackhole deadline did not retain bounded failed-member cooldown")
			}
		})
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
	if m.pool.states[0].failures != 0 || !m.pool.states[0].cooldownUntil.IsZero() {
		t.Fatal("caller cancellation penalized a healthy member")
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

func TestAsyncDNSPoolCooldownSurvivorUsesSharedBudget(t *testing.T) {
	var contacted atomic.Int32
	fast := func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}
	survivor := func(w http.ResponseWriter, r *http.Request) {
		contacted.Add(1)
		time.Sleep(80 * time.Millisecond)
		fmt.Fprint(w, poolReady)
	}
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, fast, fast, survivor)
	m.pool.mu.Lock()
	for i := 0; i < 2; i++ {
		m.pool.states[i].cooldownUntil = time.Now().Add(time.Second)
	}
	m.pool.mu.Unlock()
	start := time.Now()
	response, err := m.fetchContext(context.Background(), "fixture.example")
	if err != nil || response == nil || contacted.Load() != 1 {
		t.Fatalf("healthy survivor lost unused shared budget: response=%v err=%v calls=%d elapsed=%v", response, err, contacted.Load(), time.Since(start))
	}
	if time.Since(start) >= 150*time.Millisecond {
		t.Fatal("shared deadline exceeded")
	}
}

func TestAsyncDNSPoolFastFailuresPreserveRemainingBudget(t *testing.T) {
	var attempts atomic.Int32
	failed := func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	survivor := func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		time.Sleep(80 * time.Millisecond)
		fmt.Fprint(w, poolReady)
	}
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, failed, failed, survivor)
	start := time.Now()
	response, err := m.fetchContext(context.Background(), "fixture.example")
	if err != nil || response == nil || attempts.Load() != 3 {
		t.Fatalf("fast failures discarded shared budget: response=%v err=%v attempts=%d", response, err, attempts.Load())
	}
	if time.Since(start) >= 150*time.Millisecond {
		t.Fatal("shared deadline exceeded")
	}
}

func TestAsyncDNSPoolHealthyMembersKeepWholeBudget(t *testing.T) {
	var calls atomic.Int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		select {
		case <-time.After(80 * time.Millisecond):
			io.WriteString(w, poolReady)
		case <-r.Context().Done():
			return
		}
	}
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, handler, handler, handler)
	start := time.Now()
	response, err := m.fetchContext(context.Background(), "healthy.example")
	if err != nil || response == nil || response.Route != "ru" || calls.Load() != 3 {
		t.Fatalf("healthy member lost whole deadline: err=%v calls=%d elapsed=%v", err, calls.Load(), time.Since(start))
	}
	if time.Since(start) >= 150*time.Millisecond {
		t.Fatal("healthy response exceeded shared deadline")
	}
}

func TestAsyncDNSPoolRefusedConnectionKeepsSameOperationBudget(t *testing.T) {
	var survivor atomic.Int32
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, func(w http.ResponseWriter, r *http.Request) { t.Error("refused member served request") }, func(w http.ResponseWriter, r *http.Request) {
		survivor.Add(1)
		time.Sleep(80 * time.Millisecond)
		io.WriteString(w, poolReady)
	}, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(80 * time.Millisecond):
			io.WriteString(w, poolReady)
		case <-r.Context().Done():
		}
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := listener.Addr().String()
	listener.Close()
	transport := m.client.Transport.(*http.Transport)
	originalDial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "100.64.0.10:8090" {
			return (&net.Dialer{}).DialContext(ctx, network, refused)
		}
		return originalDial(ctx, network, address)
	}
	start := time.Now()
	response, err := m.fetchContext(context.Background(), "refused.example")
	if err != nil || response == nil || survivor.Load() != 1 || m.Stats().PoolAttempts != 3 {
		t.Fatalf("fast refusal discarded remaining budget: err=%v stats=%+v", err, m.Stats())
	}
	if time.Since(start) >= 150*time.Millisecond {
		t.Fatal("refused connection multiplied shared deadline")
	}
}

func TestAsyncDNSPoolSilentOperationRecoversWithoutFalsePenalty(t *testing.T) {
	var hung, survivor atomic.Int32
	slow := func(w http.ResponseWriter, r *http.Request) {
		survivor.Add(1)
		select {
		case <-time.After(80 * time.Millisecond):
			io.WriteString(w, poolReady)
		case <-r.Context().Done():
		}
	}
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, func(w http.ResponseWriter, r *http.Request) { hung.Add(1); <-r.Context().Done() }, slow, slow)
	start := time.Now()
	response, err := m.fetchContext(context.Background(), "hung.example")
	if err != nil || response == nil || response.Route != "ru" || hung.Load() != 1 || survivor.Load() != 2 || m.Stats().PoolAttempts != 3 || time.Since(start) >= 150*time.Millisecond {
		t.Fatalf("silent first did not recover: %v %+v", err, m.Stats())
	}
	if m.pool.states[0].failures != 0 || m.pool.endpointStats()[0].WinnerCanceled != 1 {
		t.Fatal("speculative winner cancellation inferred unhealthy endpoint")
	}
}

func TestAsyncDNSPoolZeroWaitRecoveryKeepsWarmL1(t *testing.T) {
	var primary, secondary atomic.Int32
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150, RouteWaitMillis: 0, Workers: 1}, func(w http.ResponseWriter, r *http.Request) { primary.Add(1); <-r.Context().Done() }, func(w http.ResponseWriter, r *http.Request) {
		secondary.Add(1)
		time.Sleep(80 * time.Millisecond)
		io.WriteString(w, poolReady)
	})
	now := time.Now()
	warm := asyncDNSCacheEntry{routeRU: true, generation: "known-good", freshUntil: now.Add(time.Minute), hardUntil: now.Add(2 * time.Minute), serverHardUntil: now.Add(3 * time.Minute), refreshAt: now.Add(time.Minute)}
	m.mu.Lock()
	m.putEntry("warm.example", warm)
	m.mu.Unlock()
	start := time.Now()
	if m.Apply(swrContext("cold.example")) || time.Since(start) > 30*time.Millisecond {
		t.Fatal("cold routeWait0 waited for background recovery")
	}
	if !m.Apply(swrContext("warm.example")) {
		t.Fatal("background failure discarded warm decision")
	}
	eventuallyAsyncDNS(t, func() bool { return m.Stats().Entries == 2 })
	if !m.Apply(swrContext("cold.example")) || primary.Load() != 1 || secondary.Load() != 1 || m.Stats().Requests != 1 || m.Stats().Errors != 0 {
		t.Fatalf("scheduler did not recover cold L1 after bounded failed operation: %+v", m.Stats())
	}
	m.mu.Lock()
	retained := m.cache["warm.example"]
	m.mu.Unlock()
	if retained.generation != warm.generation || !retained.freshUntil.Equal(warm.freshUntil) || !retained.hardUntil.Equal(warm.hardUntil) || m.routeWait != 0 || m.Stats().WaitStarts != 0 {
		t.Fatal("recovery changed L1 deadlines, generation or routeWait0")
	}
}
