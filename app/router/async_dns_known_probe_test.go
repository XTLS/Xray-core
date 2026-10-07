package router

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func markKnownProbe(m *AsyncDNSRouteMatcher, all bool) {
	m.pool.mu.Lock()
	defer m.pool.mu.Unlock()
	for i := range m.pool.states {
		if i == 0 || all {
			m.pool.states[i].failures = 1
			m.pool.states[i].cooldownUntil = time.Time{}
		}
	}
	m.pool.next = 0
}

func TestAsyncDNSPoolKnownProbeReservesSurvivorBudget(t *testing.T) {
	var hung, survivor atomic.Int32
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150},
		func(w http.ResponseWriter, r *http.Request) { hung.Add(1); <-r.Context().Done() },
		func(w http.ResponseWriter, r *http.Request) {
			survivor.Add(1)
			time.Sleep(80 * time.Millisecond)
			io.WriteString(w, poolReady)
		})
	for range 2 {
		markKnownProbe(m, false) // Expired passive cooldown, not a new healthy endpoint.
		start := time.Now()
		response, err := m.fetchContext(context.Background(), "probe.example")
		if err != nil || response == nil || response.Route != "ru" || time.Since(start) > 200*time.Millisecond {
			t.Fatalf("known probe exhausted survivor budget: err=%v elapsed=%v", err, time.Since(start))
		}
	}
	stats := m.pool.endpointStats()
	if hung.Load() != 2 || survivor.Load() != 2 || stats[0].Timeout != 2 || stats[1].Successes != 2 || m.Stats().PoolFailovers != 2 {
		t.Fatalf("real child timeout/failover counters wrong: %+v", stats)
	}
}

func TestAsyncDNSPoolKnownProbeRecoveryAndAllPenalizedBudget(t *testing.T) {
	for _, tc := range []struct {
		name  string
		all   bool
		delay time.Duration
	}{{"quick-recovery", false, 10 * time.Millisecond}, {"all-penalized-slow-recovery", true, 80 * time.Millisecond}} {
		t.Run(tc.name, func(t *testing.T) {
			var second atomic.Int32
			m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, func(w http.ResponseWriter, r *http.Request) { time.Sleep(tc.delay); io.WriteString(w, poolReady) }, func(w http.ResponseWriter, r *http.Request) {
				second.Add(1)
				select {
				case <-time.After(tc.delay):
					io.WriteString(w, poolReady)
				case <-r.Context().Done():
				}
			})
			markKnownProbe(m, tc.all)
			response, err := m.fetchContext(context.Background(), "recovered.example")
			if err != nil || response == nil || second.Load() != map[bool]int32{false: 0, true: 1}[tc.all] {
				t.Fatalf("recovery failed: %v", err)
			}
			m.pool.mu.Lock()
			failure := m.pool.states[0].failures
			m.pool.mu.Unlock()
			if failure != 0 {
				t.Fatal("successful recovery retained penalty")
			}
		})
	}
}

func TestAsyncDNSPoolKnownProbeTerminalAndExternalCancel(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{{"auth", 401, ""}, {"pending", 200, `{"state":"pending","retryAfterMillis":5000}`}} {
		t.Run(tc.name, func(t *testing.T) {
			var survivor atomic.Int32
			m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); io.WriteString(w, tc.body) }, func(w http.ResponseWriter, r *http.Request) { survivor.Add(1); io.WriteString(w, poolReady) })
			markKnownProbe(m, false)
			_, _ = m.fetchContext(context.Background(), "terminal.example")
			if survivor.Load() != 0 || m.Stats().PoolAttempts != 1 {
				t.Fatal("terminal known probe fanned out")
			}
		})
	}
	t.Run("external-cancel", func(t *testing.T) {
		entered := make(chan struct{})
		var survivor atomic.Int32
		m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() }, func(w http.ResponseWriter, r *http.Request) { survivor.Add(1) })
		markKnownProbe(m, false)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { _, err := m.fetchContext(ctx, "cancel.example"); done <- err }()
		select {
		case <-entered:
			cancel()
		case <-time.After(time.Second):
			t.Fatal("probe did not enter")
		}
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("parent cancellation changed: %v", err)
		}
		m.pool.mu.Lock()
		failure := m.pool.states[0].failures
		m.pool.mu.Unlock()
		if survivor.Load() != 0 || failure != 1 {
			t.Fatal("external cancellation retried or penalized endpoint")
		}
	})
}

func TestAsyncDNSPoolKnownProbeSkipsSubMillisecondBudget(t *testing.T) {
	var probe atomic.Int32
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, func(w http.ResponseWriter, r *http.Request) { probe.Add(1); <-r.Context().Done() }, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, poolReady) })
	markKnownProbe(m, false)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Microsecond)
	defer cancel()
	_, _ = m.fetchContext(ctx, "tiny.example")
	if probe.Load() != 0 || m.pool.endpointStats()[0].Attempts != 0 {
		t.Fatal("known probe spent an unusably small remaining budget")
	}
}

func TestAsyncDNSPoolKnownProbeBackgroundRecoveryKeepsZeroWait(t *testing.T) {
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150, RouteWaitMillis: 0, Workers: 1}, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(80 * time.Millisecond)
		io.WriteString(w, poolReady)
	})
	markKnownProbe(m, false)
	start := time.Now()
	if m.Apply(swrContext("cold-probe.example")) || time.Since(start) > 30*time.Millisecond {
		t.Fatal("cold routeWait0 blocked")
	}
	deadline := time.Now().Add(3 * time.Second)
	for !m.Apply(swrContext("cold-probe.example")) {
		if time.Now().After(deadline) {
			t.Fatalf("background survivor did not fill L1: %+v", m.Stats())
		}
		time.Sleep(10 * time.Millisecond)
	}
	stats := m.Stats()
	if stats.Errors != 0 || stats.Requests != 1 || stats.Successes != 1 || stats.WaitStarts != 0 {
		t.Fatalf("known probe failed background job: %+v", stats)
	}
	before := stats.PoolAttempts
	if !m.Apply(swrContext("cold-probe.example")) || m.Stats().PoolAttempts != before {
		t.Fatal("warm L1 decision generated another lookup")
	}
}

func TestAsyncDNSPoolKnownSlowProbeDoesNotDisplaceHealthyPeer(t *testing.T) {
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(80 * time.Millisecond):
			io.WriteString(w, poolReady)
		case <-r.Context().Done():
		}
	}, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, poolReady) })
	markKnownProbe(m, false)
	response, err := m.fetchContext(context.Background(), "slow-known.example")
	if err != nil || response == nil {
		t.Fatalf("healthy successor lost to slow probe: %v", err)
	}
	m.pool.mu.Lock()
	failure := m.pool.states[0].failures
	m.pool.mu.Unlock()
	if failure != 2 || m.pool.endpointStats()[1].Successes != 1 {
		t.Fatal("known slow probe unexpectedly promoted or displaced healthy peer")
	}
}
