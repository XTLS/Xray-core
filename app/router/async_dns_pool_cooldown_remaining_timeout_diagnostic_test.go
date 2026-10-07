package router

import (
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestAsyncDNSPoolExpiredDeadHeaderStallDoesNotOmitCooledFastPeer(t *testing.T) {
	var calls [3]atomic.Int32
	var active atomic.Int32
	handler := func(i int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			calls[i].Add(1)
			active.Add(1)
			defer active.Add(-1)
			if i == 2 {
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
	m.pool.next = 1
	started := time.Now()
	response, err := m.fetchContext(context.Background(), "fixture.example")
	if err != nil || response == nil || response.Generation != "same-fill" || time.Since(started) >= 150*time.Millisecond {
		t.Fatalf("known-state hole remains: %v", err)
	}
	for i := range calls {
		if calls[i].Load() != 1 {
			t.Fatalf("member%d omitted", i)
		}
	}
	deadline := time.Now().Add(time.Second)
	for active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active.Load() != 0 {
		t.Fatal("undrained handlers")
	}
	if samples, _ := m.pool.failureSamples.take(); len(samples) != 0 {
		t.Fatal("successful job fabricated failure")
	}
	if m.pool.states[0].failures != 6 || m.pool.states[1].failures != 0 {
		t.Fatal("winner cancellation penalized passive health")
	}
}
