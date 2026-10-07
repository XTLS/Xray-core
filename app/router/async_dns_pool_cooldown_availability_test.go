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

func coolPoolMember(m *AsyncDNSRouteMatcher, index int, failures uint8, until time.Time) {
	m.pool.mu.Lock()
	defer m.pool.mu.Unlock()
	m.pool.states[index].failures = failures
	m.pool.states[index].cooldownUntil = until
}

func TestAsyncDNSPoolCooldownReservesAllThreeInLeastFailedOrder(t *testing.T) {
	fast := func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, poolReady) }
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, fast, fast, fast)
	now := time.Now()
	coolPoolMember(m, 0, 6, now.Add(time.Second))
	coolPoolMember(m, 1, 1, now.Add(2*time.Second))
	coolPoolMember(m, 2, 1, now.Add(time.Second))
	candidates, skipped := m.pool.candidates(now)
	if len(candidates) != 3 || candidates[0].endpoint != m.pool.states[2].endpoint || candidates[1].endpoint != m.pool.states[1].endpoint || skipped != 0 {
		t.Fatalf("wrong bounded least-bad reserve: %+v skipped=%d", candidates, skipped)
	}
	for _, candidate := range candidates {
		if !candidate.knownFailed {
			t.Fatal("cooled fallback invented healthy state")
		}
	}
	if m.pool.states[0].metrics.cooldownSkips.Load() != 0 || m.pool.states[1].metrics.cooldownSkips.Load() != 0 || m.pool.states[2].metrics.cooldownSkips.Load() != 0 {
		t.Fatal("reserved fallback falsely counted skipped")
	}
}

func TestAsyncDNSPoolAllCooldownRecoversWithoutSyntheticFailure(t *testing.T) {
	var calls [3]atomic.Int32
	dead := func(w http.ResponseWriter, r *http.Request) { calls[0].Add(1); <-r.Context().Done() }
	healthy := func(i int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { calls[i].Add(1); io.WriteString(w, poolReady) }
	}
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, dead, healthy(1), healthy(2))
	until := time.Now().Add(time.Second)
	coolPoolMember(m, 0, 6, until)
	coolPoolMember(m, 1, 1, until)
	coolPoolMember(m, 2, 1, until)
	response, err := m.fetchContext(context.Background(), "all-cooling.example")
	if err != nil || response == nil || response.Generation != "same-fill" || m.Stats().PoolSyntheticCooldown != 0 || calls[0].Load() != 0 || calls[1].Load()+calls[2].Load() != 1 {
		t.Fatalf("cooldown became outage: response=%v err=%v calls=%d/%d/%d stats=%+v", response, err, calls[0].Load(), calls[1].Load(), calls[2].Load(), m.Stats())
	}
}

func TestAsyncDNSPoolOneEligibleStallUsesCooledBackup(t *testing.T) {
	var calls [3]atomic.Int32
	var active, maxActive atomic.Int32
	handler := func(i int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			calls[i].Add(1)
			n := active.Add(1)
			defer active.Add(-1)
			for old := maxActive.Load(); n > old && !maxActive.CompareAndSwap(old, n); old = maxActive.Load() {
			}
			if i == 0 {
				select {
				case <-time.After(120 * time.Millisecond):
					io.WriteString(w, poolReady)
				case <-r.Context().Done():
				}
				return
			}
			if i == 2 {
				<-r.Context().Done()
				return
			}
			select {
			case <-time.After(20 * time.Millisecond):
				io.WriteString(w, `{"state":"ready","route":"other","ttlMillis":5000,"generation":"cooled-backup"}`)
			case <-r.Context().Done():
			}
		}
	}
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, handler(0), handler(1), handler(2))
	until := time.Now().Add(time.Second)
	coolPoolMember(m, 1, 1, until)
	coolPoolMember(m, 2, 6, until)
	started := time.Now()
	response, err := m.fetchContext(context.Background(), "one-eligible.example")
	if err != nil || response == nil || response.Generation != "cooled-backup" || time.Since(started) >= 150*time.Millisecond || calls[0].Load() != 1 || calls[1].Load() != 1 || calls[2].Load() != 1 || maxActive.Load() > 3 {
		t.Fatalf("sole eligible lost redundancy: response=%v err=%v calls=%d/%d/%d elapsed=%v max=%d", response, err, calls[0].Load(), calls[1].Load(), calls[2].Load(), time.Since(started), maxActive.Load())
	}
	deadline := time.Now().Add(time.Second)
	for active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active.Load() != 0 {
		t.Fatal("losing HTTP attempt leaked")
	}
	stats := m.pool.endpointStats()
	if stats[0].WinnerCanceled != 1 || stats[0].Timeout != 0 || stats[1].Successes != 1 || stats[2].WinnerCanceled != 1 {
		t.Fatalf("real endpoint accounting lost: %+v", stats)
	}
}

func TestAsyncDNSPoolAllCooldownAllFailBounded(t *testing.T) {
	var calls, active, maxActive atomic.Int32
	silent := func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		n := active.Add(1)
		defer active.Add(-1)
		for old := maxActive.Load(); n > old && !maxActive.CompareAndSwap(old, n); old = maxActive.Load() {
		}
		<-r.Context().Done()
	}
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, silent, silent, silent)
	until := time.Now().Add(time.Second)
	for i := range 3 {
		coolPoolMember(m, i, 1, until)
	}
	started := time.Now()
	_, err := m.fetchContext(context.Background(), "all-failed.example")
	if !errors.Is(err, context.DeadlineExceeded) || calls.Load() != 3 || maxActive.Load() > 3 || time.Since(started) > 230*time.Millisecond || m.Stats().PoolSyntheticCooldown != 0 {
		t.Fatalf("all-fail escaped configured deadline/attempt bounds: err=%v calls=%d active=%d elapsed=%v", err, calls.Load(), maxActive.Load(), time.Since(started))
	}
	deadline := time.Now().Add(time.Second)
	for active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active.Load() != 0 {
		t.Fatal("all-fail HTTP attempt leaked")
	}
	rows := m.pool.endpointStats()
	if rows[0].Timeout+rows[1].Timeout+rows[2].Timeout != 3 {
		t.Fatalf("all-fail real errors not visible: %+v", rows)
	}
}

func TestAsyncDNSPoolCooldownKeepsOrdinaryOrderAndRecovery(t *testing.T) {
	fast := func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, poolReady) }
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, fast, fast, fast)
	now := time.Now()
	until := now.Add(time.Second)
	coolPoolMember(m, 0, 6, until)
	m.pool.next = 2
	candidates, skipped := m.pool.candidates(now)
	if len(candidates) != 3 || candidates[0].endpoint != m.pool.states[2].endpoint || candidates[1].endpoint != m.pool.states[1].endpoint || skipped != 0 {
		t.Fatalf("ordinary eligible order changed: %+v", candidates)
	}
	m.pool.next = 0
	candidates, skipped = m.pool.candidates(until.Add(time.Millisecond))
	if len(candidates) != 3 || candidates[0].endpoint != m.pool.states[0].endpoint || !candidates[0].knownFailed || skipped != 0 {
		t.Fatalf("expired failed member lost ordinary recovery probe: %+v", candidates)
	}
	m.pool.record(m.pool.states[0].endpoint, false, until)
	if m.pool.states[0].failures != 0 || !m.pool.states[0].cooldownUntil.IsZero() {
		t.Fatal("success did not clear passive failure state")
	}
}

func TestAsyncDNSPoolAllCooldownAuthRemainsTerminal(t *testing.T) {
	var calls atomic.Int32
	auth := func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(http.StatusUnauthorized) }
	ready := func(w http.ResponseWriter, r *http.Request) { calls.Add(1); io.WriteString(w, poolReady) }
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, auth, ready, ready)
	until := time.Now().Add(time.Second)
	for i := range 3 {
		coolPoolMember(m, i, 1, until)
	}
	_, err := m.fetchContext(context.Background(), "auth.example")
	if err == nil || calls.Load() != 1 || m.Stats().PoolAttempts != 1 {
		t.Fatalf("cooldown fallback bypassed auth terminal: err=%v calls=%d", err, calls.Load())
	}
}
