package router

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

// Exercise refresh synchronously so the assertions observe one complete HTTP
// attempt, without a scheduler starting another attempt between observations.
func refreshSemanticsMatcher(t *testing.T, endpoint string, grace time.Duration) *AsyncDNSRouteMatcher {
	t.Helper()
	m := projectionMatcher(grace)
	m.endpoint = endpoint
	m.client = &http.Client{Timeout: 2 * time.Second}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.jobs = make(map[string]*asyncDNSJob)
	m.queue = make(chan string, 2)
	m.stop = make(chan struct{})
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func refreshSemanticsJob(m *AsyncDNSRouteMatcher, domain string) time.Time {
	deadline := time.Now().Add(5 * time.Second)
	m.jobs[domain] = &asyncDNSJob{deadline: deadline, attempts: 1, queued: true}
	return deadline
}

func assertRefreshSemanticsRetry(t *testing.T, m *AsyncDNSRouteMatcher, domain string, deadline, earliest time.Time) {
	t.Helper()
	job, ok := m.jobs[domain]
	if !ok {
		t.Fatal("non-fresh response discarded the retry job")
	}
	if job.deadline != deadline || job.attempts != 1 || job.queued || job.exhausted {
		t.Fatalf("response reset the existing retry budget: %+v", job)
	}
	if job.next.Before(earliest) || job.next.After(deadline) {
		t.Fatalf("retry is immediate or exceeds its original budget: next=%v earliest=%v deadline=%v", job.next, earliest, deadline)
	}
}

func TestAsyncDNSRefreshExpiredReadyIsSuccessfulAndKeepsRetryBudget(t *testing.T) {
	for _, tc := range []struct {
		name       string
		grace      time.Duration
		staleTTL   string
		wantUsable bool
	}{
		{name: "remaining_stale", grace: time.Second, staleTTL: "2000", wantUsable: true},
		{name: "stale_disabled", staleTTL: "2000"},
		{name: "legacy_without_stale", grace: time.Second, staleTTL: "0"},
		{name: "server_hard_expired", grace: time.Second, staleTTL: "1"},
		{name: "local_grace_expired", grace: time.Millisecond, staleTTL: "2000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// The reply was valid when prepared, but its one millisecond of
				// freshness cannot survive this actual HTTP exchange.
				time.Sleep(20 * time.Millisecond)
				_, _ = io.WriteString(w, `{"state":"ready","route":"ru","ttlMillis":1,"staleTtlMillis":`+tc.staleTTL+`,"generation":"fill-expired"}`)
			}))
			defer server.Close()
			m := refreshSemanticsMatcher(t, server.URL, tc.grace)
			const domain = "expired-in-flight.example"
			deadline := refreshSemanticsJob(m, domain)
			before := time.Now()
			m.refresh(domain)
			stats := m.Stats()
			if stats.Requests != 1 || stats.Successes != 1 || stats.ExpiredResponses != 1 || stats.Errors != 0 || stats.InvalidResponses != 0 {
				t.Fatalf("ordinary expiry was not classified as a successful expired response: %+v", stats)
			}
			if got := m.Apply(swrContext(domain)); got != tc.wantUsable {
				t.Fatalf("expired response routing=%v, want usable stale=%v", got, tc.wantUsable)
			}
			assertRefreshSemanticsRetry(t, m, domain, deadline, before.Add(200*time.Millisecond))
		})
	}
}

func TestAsyncDNSExpiredReadyAnchorsGraceBeforeArrival(t *testing.T) {
	started := time.Now()
	now := started.Add(100 * time.Millisecond)
	for _, tc := range []struct {
		name     string
		grace    time.Duration
		staleTTL uint32
		wantHard time.Time
	}{
		{name: "local_grace", grace: 200 * time.Millisecond, staleTTL: 1000, wantHard: started.Add(220 * time.Millisecond)},
		{name: "server_hard", grace: time.Second, staleTTL: 150, wantHard: started.Add(150 * time.Millisecond)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := projectionMatcher(tc.grace)
			response := &asyncDNSClassifierResponse{State: "ready", Route: "ru", TTLMillis: 20, StaleTTLMillis: tc.staleTTL, Generation: "fill-1"}
			if m.acceptResponse("delayed.example", response, started, now) {
				t.Fatal("expired ready incorrectly completed the fresh lookup")
			}
			entry, ok := m.cache["delayed.example"]
			if !ok || !entry.routeRU || entry.freshUntil.After(now) || entry.hardUntil != tc.wantHard {
				t.Fatalf("stale grace was lost or renewed from arrival: got=%+v want hard=%v", entry, tc.wantHard)
			}
			if entry.serverHardUntil != started.Add(time.Duration(tc.staleTTL)*time.Millisecond) {
				t.Fatal("response transit extended the authoritative hard deadline")
			}
		})
	}
}

func TestAsyncDNSExpiredReadyCannotReplaceFreshOrRenewPreviousBounds(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name      string
		previous  asyncDNSCacheEntry
		unchanged bool
	}{
		{name: "still_fresh", previous: asyncDNSCacheEntry{generation: "old", freshUntil: now.Add(time.Second), hardUntil: now.Add(2 * time.Second), serverHardUntil: now.Add(3 * time.Second)}, unchanged: true},
		{name: "bounded_stale", previous: asyncDNSCacheEntry{generation: "old", freshUntil: now.Add(-time.Second), hardUntil: now.Add(40 * time.Millisecond), serverHardUntil: now.Add(50 * time.Millisecond)}},
		{name: "expired_tombstone", previous: asyncDNSCacheEntry{generation: "old", freshUntil: now.Add(-time.Second), hardUntil: now.Add(-time.Millisecond), serverHardUntil: now.Add(time.Second)}, unchanged: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := projectionMatcher(time.Second)
			m.cache["retained.example"] = tc.previous
			response := &asyncDNSClassifierResponse{State: "ready", Route: "ru", TTLMillis: 20, StaleTTLMillis: 5000, Generation: "new-but-expired"}
			if m.acceptResponse("retained.example", response, now.Add(-100*time.Millisecond), now) {
				t.Fatal("expired ready must continue refreshing")
			}
			entry := m.cache["retained.example"]
			if tc.unchanged && entry != tc.previous {
				t.Fatalf("expired response replaced fresh state or resurrected a tombstone: before=%+v after=%+v", tc.previous, entry)
			}
			if entry.hardUntil.After(tc.previous.hardUntil) || entry.serverHardUntil.After(tc.previous.serverHardUntil) {
				t.Fatal("an expired new generation extended previous retention")
			}
		})
	}
}

func TestAsyncDNSSameGenerationDoesNotScheduleShrinkingPrefetch(t *testing.T) {
	for _, tc := range []struct{ name, before, after string }{
		{name: "same_generation", before: "fill-1", after: "fill-1"},
		{name: "legacy_generation"},
		{name: "previous_unknown", after: "fill-1"},
		{name: "response_unknown", before: "fill-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := projectionMatcher(time.Second)
			started := time.Now()
			first := &asyncDNSClassifierResponse{State: "ready", Route: "ru", TTLMillis: 10000, StaleTTLMillis: 20000, Generation: tc.before}
			if !m.acceptResponse("same.example", first, started, started) {
				t.Fatal("initial classification was not accepted")
			}
			initial := m.cache["same.example"]
			if !initial.refreshAt.Before(initial.freshUntil) {
				t.Fatal("first classification lost proactive refresh")
			}
			// Repeated reads of one DNS fill must not schedule another query
			// inside an ever-smaller fraction of its remaining lifetime.
			for _, elapsed := range []time.Duration{8 * time.Second, 9 * time.Second, 9900 * time.Millisecond} {
				now := started.Add(elapsed)
				response := &asyncDNSClassifierResponse{State: "ready", Route: "ru", TTLMillis: uint32((10*time.Second - elapsed).Milliseconds()), StaleTTLMillis: uint32((20*time.Second - elapsed).Milliseconds()), Generation: tc.after}
				if !m.acceptResponse("same.example", response, now, now) {
					t.Fatal("still-fresh shared cache result rejected")
				}
				entry := m.cache["same.example"]
				if entry.refreshAt != initial.freshUntil || entry.freshUntil != initial.freshUntil {
					t.Fatalf("same fill scheduled a pre-expiry reread: %+v", entry)
				}
				if entry.hardUntil.After(initial.hardUntil) || entry.serverHardUntil.After(initial.serverHardUntil) {
					t.Fatal("reread extended generation retention")
				}
			}
		})
	}
}

func TestAsyncDNSNewGenerationStillReplacesRouteAndPrefetches(t *testing.T) {
	m := projectionMatcher(time.Second)
	m.maxTTL = 2 * time.Second
	now := time.Now()
	first := &asyncDNSClassifierResponse{State: "ready", Route: "ru", TTLMillis: 10000, StaleTTLMillis: 20000, Generation: "fill-1"}
	m.acceptResponse("changed.example", first, now, now)
	later := now.Add(time.Second)
	second := &asyncDNSClassifierResponse{State: "ready", Route: "other", TTLMillis: 10000, StaleTTLMillis: 20000, Generation: "fill-2"}
	if !m.acceptResponse("changed.example", second, later, later) {
		t.Fatal("fresh new generation rejected")
	}
	entry := m.cache["changed.example"]
	if entry.routeRU || entry.generation != "fill-2" {
		t.Fatal("new classification failed to replace RU immediately")
	}
	if !entry.refreshAt.After(later) || !entry.refreshAt.Before(entry.freshUntil) || entry.freshUntil != later.Add(m.maxTTL) {
		t.Fatalf("new generation lost prefetch or local maxTTL bound: %+v", entry)
	}
}

func TestAsyncDNSMalformedSuccessfulHTTPResponsesRemainErrors(t *testing.T) {
	for _, body := range []string{
		`{"state":"ready","route":"ru","ttlMillis":0,"staleTtlMillis":5000}`,
		`{"state":"ready","route":"ru","ttlMillis":100,"staleTtlMillis":50}`,
		`{"state":"pending","route":"ru"}`,
		`{"state":"pending","ttlMillis":1}`,
		`{"state":"pending","staleTtlMillis":1}`,
		`{"state":"pending","generation":"unexpected"}`,
		`{"state":"stale","route":"ru","ttlMillis":1,"staleTtlMillis":5000}`,
		`{"state":"stale","route":"ru","staleTtlMillis":0}`,
		`{"state":"stale","route":"unknown","staleTtlMillis":5000}`,
		`{"state":"stale","route":"ru","staleTtlMillis":5000,"generation":"` + strings.Repeat("x", 129) + `"}`,
		`{"state":"unknown","route":"ru","ttlMillis":100}`,
		`null`,
		`{"state":`,
	} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }))
			defer server.Close()
			m := refreshSemanticsMatcher(t, server.URL, time.Second)
			const domain = "invalid-reply.example"
			before := time.Now()
			previous := asyncDNSCacheEntry{routeRU: true, freshUntil: before.Add(time.Second), hardUntil: before.Add(2 * time.Second), serverHardUntil: before.Add(3 * time.Second), generation: "known-good"}
			m.cache[domain] = previous
			deadline := refreshSemanticsJob(m, domain)
			m.refresh(domain)
			stats := m.Stats()
			if stats.Requests != 1 || stats.Errors != 1 || stats.InvalidResponses != 1 || stats.Successes != 0 || stats.ExpiredResponses != 0 {
				t.Fatalf("malformed response was hidden as normal expiry/pending: %+v", stats)
			}
			entry := m.cache[domain]
			if !entry.routeRU || entry.freshUntil != previous.freshUntil || entry.hardUntil != previous.hardUntil || entry.serverHardUntil != previous.serverHardUntil || entry.generation != previous.generation {
				t.Fatal("malformed response damaged last-good routing state")
			}
			assertRefreshSemanticsRetry(t, m, domain, deadline, before.Add(200*time.Millisecond))
		})
	}
}

func TestAsyncDNSValidPendingAndDisabledStaleRemainSuccessful(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		pending    bool
	}{
		{name: "pending", body: `{"state":"pending","retryAfterMillis":1}`, pending: true},
		{name: "stale_disabled", body: `{"state":"stale","route":"ru","staleTtlMillis":1000}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, tc.body) }))
			defer server.Close()
			m := refreshSemanticsMatcher(t, server.URL, 0)
			const domain = "not-ready.example"
			before := time.Now()
			deadline := refreshSemanticsJob(m, domain)
			m.refresh(domain)
			stats := m.Stats()
			if stats.Successes != 1 || stats.Errors != 0 || stats.InvalidResponses != 0 {
				t.Fatalf("valid non-fresh reply counted as a failure: %+v", stats)
			}
			if tc.pending && stats.PendingResponses != 1 || !tc.pending && stats.StaleResponses != 1 {
				t.Fatalf("wrong successful response category: %+v", stats)
			}
			if m.Apply(swrContext(domain)) {
				t.Fatal("reply created an unpermitted RU route")
			}
			assertRefreshSemanticsRetry(t, m, domain, deadline, before.Add(200*time.Millisecond))
		})
	}
}

func TestAsyncDNSRefreshFailureCategoriesKeepLastGoodAndRetry(t *testing.T) {
	for _, tc := range []struct {
		name       string
		handler    http.HandlerFunc
		prepare    func(*AsyncDNSRouteMatcher)
		wantMetric func(AsyncDNSRouteStats) uint64
	}{
		{name: "http_unauthorized", handler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) }, wantMetric: func(s AsyncDNSRouteStats) uint64 { return s.HTTPErrors }},
		{name: "http_unavailable", handler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }, wantMetric: func(s AsyncDNSRouteStats) uint64 { return s.HTTPErrors }},
		{name: "response_timeout", handler: func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(time.Second):
			}
		}, prepare: func(m *AsyncDNSRouteMatcher) { m.client.Timeout = 20 * time.Millisecond }, wantMetric: func(s AsyncDNSRouteStats) uint64 { return s.TimeoutErrors }},
		{name: "context_canceled", prepare: func(m *AsyncDNSRouteMatcher) { m.cancel() }, wantMetric: func(s AsyncDNSRouteStats) uint64 { return s.CanceledErrors }},
		{name: "response_connection_aborted", handler: func(w http.ResponseWriter, r *http.Request) { panic(http.ErrAbortHandler) }, wantMetric: func(s AsyncDNSRouteStats) uint64 { return s.TransportErrors }},
		{name: "response_too_large", handler: func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, strings.Repeat("x", 32*1024+1)) }, wantMetric: func(s AsyncDNSRouteStats) uint64 { return s.InvalidResponses }},
		{name: "invalid_request_url", prepare: func(m *AsyncDNSRouteMatcher) { m.endpoint = ":invalid-url" }, wantMetric: func(s AsyncDNSRouteStats) uint64 { return s.RequestErrors }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := tc.handler
			if handler == nil {
				handler = func(w http.ResponseWriter, r *http.Request) {
					t.Error("request reached server despite a preflight failure")
				}
			}
			server := httptest.NewServer(handler)
			defer server.Close()
			m := refreshSemanticsMatcher(t, server.URL, time.Second)
			const domain = "failed-refresh.example"
			before := time.Now()
			previous := asyncDNSCacheEntry{routeRU: true, freshUntil: before.Add(10 * time.Second), hardUntil: before.Add(11 * time.Second), serverHardUntil: before.Add(20 * time.Second), generation: "last-good"}
			m.cache[domain] = previous
			deadline := refreshSemanticsJob(m, domain)
			if tc.prepare != nil {
				tc.prepare(m)
			}
			m.refresh(domain)
			stats := m.Stats()
			classifiedErrors := stats.TimeoutErrors + stats.CanceledErrors + stats.TransportErrors + stats.HTTPErrors + stats.InvalidResponses + stats.RequestErrors
			if stats.Requests != 1 || stats.Errors != 1 || stats.Successes != 0 || tc.wantMetric(stats) != 1 || classifiedErrors != 1 {
				t.Fatalf("failure did not increment exactly its diagnostic category: %+v", stats)
			}
			entry := m.cache[domain]
			if !entry.routeRU || entry.freshUntil != previous.freshUntil || entry.hardUntil != previous.hardUntil || entry.serverHardUntil != previous.serverHardUntil || entry.generation != previous.generation {
				t.Fatal("failed refresh erased or altered last-good routing state")
			}
			assertRefreshSemanticsRetry(t, m, domain, deadline, before.Add(200*time.Millisecond))
		})
	}
}

func TestAsyncDNSIdenticalReloadPreservesSameGenerationRecheck(t *testing.T) {
	config := asyncReloadConfig("https://example.invalid")
	r := new(Router)
	if err := r.Init(context.Background(), config, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	old := currentAsync(r)
	started := time.Now()
	old.mu.Lock()
	old.acceptResponse("reload-schedule.example", &asyncDNSClassifierResponse{State: "ready", Route: "ru", TTLMillis: 10000, StaleTTLMillis: 20000, Generation: "fill-1"}, started, started)
	later := started.Add(8 * time.Second)
	old.acceptResponse("reload-schedule.example", &asyncDNSClassifierResponse{State: "ready", Route: "ru", TTLMillis: 2000, StaleTTLMillis: 12000, Generation: "fill-1"}, later, later)
	previous := old.cache["reload-schedule.example"]
	old.mu.Unlock()
	if previous.refreshAt != previous.freshUntil {
		t.Fatal("test did not establish an expiry-bound reread")
	}
	if err := r.ReloadRules(proto.Clone(config).(*Config), false); err != nil {
		t.Fatal(err)
	}
	next := currentAsync(r)
	next.mu.Lock()
	inherited := next.cache["reload-schedule.example"]
	next.mu.Unlock()
	if next == old || !old.closed.Load() || inherited != previous {
		t.Fatalf("reload altered same-generation schedule or deadlines: before=%+v after=%+v", previous, inherited)
	}
}
