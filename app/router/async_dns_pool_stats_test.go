package router

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAsyncDNSPoolAttemptStatsIncludeRecoveredTransportFailure(t *testing.T) {
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150},
		func(w http.ResponseWriter, r *http.Request) { t.Error("refused address reached HTTP") },
		func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, poolReady) },
	)
	tr := m.client.Transport.(*http.Transport)
	dial := tr.DialContext
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "100.64.0.10:8090" {
			return nil, errors.New("refused: private-domain bearer-secret")
		}
		return dial(ctx, network, address)
	}
	if _, err := m.fetch("private-domain.example"); err != nil {
		t.Fatal(err)
	}
	s := m.pool.endpointStats()
	if s[0].Attempts != 1 || s[0].Transport != 1 || s[1].Attempts != 1 || s[1].Successes != 1 || m.Stats().PoolFailovers != 1 {
		t.Fatalf("recovered attempt hidden: %+v", s)
	}
	if _, err := m.fetch("second.example"); err != nil {
		t.Fatal(err)
	}
	s = m.pool.endpointStats()
	if s[0].CooldownSkips != 0 || s[0].Attempts != 1 || s[1].Successes != 2 {
		t.Fatalf("reserved fallback falsely skipped or launched on fast healthy: %+v", s)
	}
	for i, v := range s {
		line := v.logLine(7, i)
		for _, secret := range []string{"private-domain", "bearer-secret", "http://", "100.64"} {
			if strings.Contains(line, secret) {
				t.Fatal("log exposed private input")
			}
		}
	}
}

func TestAsyncDNSPoolAttemptStatsTerminalResultsDoNotFanOut(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		status                 int
		body                   string
		pending, http, invalid uint64
	}{
		{"pending", 200, `{"state":"pending","retryAfterMillis":5000}`, 1, 0, 0},
		{"auth", 401, "", 0, 1, 0},
		{"forbidden", 403, "", 0, 1, 0},
		{"overload", 429, "", 0, 1, 0},
		{"other-http", 500, "", 0, 1, 0},
		{"invalid-json", 200, "{", 0, 0, 1},
		{"invalid-shape", 200, `{"state":"invalid"}`, 0, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); io.WriteString(w, tc.body) }, func(w http.ResponseWriter, r *http.Request) { t.Error("terminal result retried") })
			_, _ = m.fetch("terminal.example")
			s := m.pool.endpointStats()
			if s[0].Attempts != 1 || s[1].Attempts != 0 || s[0].Pending != tc.pending || s[0].HTTP != tc.http || s[0].Invalid != tc.invalid {
				t.Fatalf("terminal counters wrong: %+v", s)
			}
			codeCount := s[0].HTTP401 + s[0].HTTP403 + s[0].HTTP429 + s[0].HTTPOther
			if codeCount != tc.http {
				t.Fatalf("HTTP category lost: %+v", s)
			}
		})
	}
}

func TestAsyncDNSPoolAttemptStatsRecoveredHTTPStatus(t *testing.T) {
	for _, status := range []int{502, 503, 504} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, poolReady) })
			if _, err := m.fetch("retry.example"); err != nil {
				t.Fatal(err)
			}
			s := m.pool.endpointStats()
			codes := map[int]uint64{502: s[0].HTTP502, 503: s[0].HTTP503, 504: s[0].HTTP504}
			if s[0].HTTP != 1 || codes[status] != 1 || s[0].HTTPOther != 0 || s[1].Successes != 1 || m.Stats().Errors != 0 {
				t.Fatalf("recovered HTTP failure hidden or counted as job failure: %+v", s)
			}
		})
	}
}

func TestAsyncDNSPoolAttemptStatsTimeoutAndCancellationPreserveHealth(t *testing.T) {
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		io.WriteString(w, poolReady)
	})
	markKnownProbe(m, false)
	_, err := m.fetch("silent.example")
	if err != nil {
		t.Fatal("known silent probe lost surviving endpoint")
	}
	s := m.pool.endpointStats()
	if s[0].Timeout != 1 || s[0].Attempts != 1 || s[1].Attempts != 1 || s[0].ElapsedLE150+s[0].ElapsedGT150 != 1 {
		t.Fatalf("silent attempt not attributed: %+v", s)
	}
	if _, err = m.fetch("survivor.example"); err != nil {
		t.Fatal(err)
	}
	s = m.pool.endpointStats()
	if s[1].Successes != 2 || s[0].CooldownSkips != 0 || s[0].Attempts != 1 {
		t.Fatalf("passive recovery changed: %+v", s)
	}
	// Cancellation happens after the request starts, so it is an attempt; it must
	// not be mistaken for an unhealthy backend or cause another HTTP attempt.
	started := make(chan struct{})
	c := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }, func(w http.ResponseWriter, r *http.Request) { t.Error("cancellation fanned out") })
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-started; cancel() }()
	_, _ = c.fetchContext(ctx, "cancel.example")
	z := c.pool.endpointStats()
	c.pool.mu.Lock()
	failures := c.pool.states[0].failures
	c.pool.mu.Unlock()
	if z[0].Canceled != 1 || z[1].Attempts != 0 || failures != 0 {
		t.Fatalf("cancellation penalized health: %+v", z)
	}
}

func TestAsyncDNSPoolAttemptStatsSixIndicesConcurrentAndElapsedBounds(t *testing.T) {
	handlers := make([]http.HandlerFunc, 6)
	for i := range handlers {
		handlers[i] = func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, poolReady) }
	}
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, handlers...)
	if len(m.pool.endpointStats()) != 6 {
		t.Fatal("observability changed six-endpoint contract")
	}
	var wg sync.WaitGroup
	for i := range 6 {
		for _, elapsed := range []time.Duration{50, 100, 150, 151} {
			wg.Add(1)
			go func(index int, ms time.Duration) {
				defer wg.Done()
				m.pool.observe(m.pool.states[index].endpoint, &asyncDNSClassifierResponse{State: "pending"}, nil, ms*time.Millisecond)
			}(i, elapsed)
		}
	}
	wg.Wait()
	for i, s := range m.pool.endpointStats() {
		if s.Attempts != 4 || s.Successes != 4 || s.Pending != 4 || s.ElapsedLE50 != 1 || s.ElapsedLE100 != 2 || s.ElapsedLE150 != 3 || s.ElapsedGT150 != 1 {
			t.Fatalf("index%d raced or elapsed bounds wrong: %+v", i, s)
		}
		if !strings.Contains(s.logLine(9, i), "endpointIndex=") {
			t.Fatal("index missing")
		}
	}
}
