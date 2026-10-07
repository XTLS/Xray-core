package router

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// SOURCE diagnostic: this deterministic scheduling state is a hypothesis for
// the retained fault, not proof of its unobserved per-job candidate ordering.
func TestAsyncDNSPoolExpiredDeadPlusHeaderStallLeavesCooledFastPeerUnused(t *testing.T) {
	var calls [3]atomic.Int32
	var active atomic.Int32
	handler := func(index int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			calls[index].Add(1)
			active.Add(1)
			defer active.Add(-1)
			if index == 2 {
				io.WriteString(w, poolReady)
				return
			}
			<-r.Context().Done()
		}
	}
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, handler(0), handler(1), handler(2))
	now := time.Now()
	coolPoolMember(m, 0, 6, now.Add(-time.Second))
	coolPoolMember(m, 2, 1, now.Add(time.Second))
	m.pool.mu.Lock()
	m.pool.next = 1
	m.pool.mu.Unlock()
	response, err := m.fetchContext(context.Background(), "diagnostic.example")
	if response != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected current-source deadline loss, response=%v err=%v", response, err)
	}
	if calls[0].Load() != 1 || calls[1].Load() != 1 || calls[2].Load() != 0 {
		t.Fatalf("unexpected candidates called: %d/%d/%d", calls[0].Load(), calls[1].Load(), calls[2].Load())
	}
	deadline := time.Now().Add(250 * time.Millisecond)
	for active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active.Load() != 0 {
		t.Fatal("canceled requests left active handlers")
	}
	if m.Stats().PoolSyntheticCooldown != 0 {
		t.Fatal("this failure is not synthetic all-cooldown")
	}
	raw, discarded := m.pool.failureSamples.take()
	if len(raw) != 1 || discarded != 0 {
		t.Fatalf("lost failed job %d/%d", len(raw), discarded)
	}
	var sample asyncDNSPoolFailureSample
	if err := json.Unmarshal([]byte(raw[0]), &sample); err != nil {
		t.Fatal(err)
	}
	if sample.Terminal != "deadline" || !sample.Deadline || sample.Budget != 150000 || sample.MaxConcurrent != 2 || len(sample.Attempts) != 2 || len(sample.Candidates) != 3 {
		t.Fatalf("wrong job %+v", sample)
	}
	if sample.Candidates[0].Failures != 6 || sample.Candidates[0].Cooldown != 0 || !sample.Candidates[0].Selected || sample.Candidates[1].Ordinal != 0 || sample.Candidates[2].Selected || sample.Candidates[2].Failures != 1 || sample.Candidates[2].Cooldown <= 0 {
		t.Fatalf("lost same-selection evidence %+v", sample.Candidates)
	}
	seen := map[int]bool{}
	for _, a := range sample.Attempts {
		seen[a.Index] = true
		if a.Terminal != "deadline" || a.Phase != asyncDNSHTTPHeaders || a.Acquire < 0 || a.Wrote < 0 || a.FirstByte != -1 || a.ChildBudget <= 0 || a.Remaining <= 0 {
			t.Fatalf("lost attempt %+v", a)
		}
	}
	if !seen[0] || !seen[1] || seen[2] {
		t.Fatal("unlaunched attempt fabricated")
	}
	t.Log("reproduced: expired six-failure member is eligible, one-failure cooled fast peer omitted, remaining two slots hit shared configured deadline; no production correlation claimed")
}
