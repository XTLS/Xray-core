package router

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAsyncDNSPoolMax3EachSoleHealthy80AndTwoSilent(t *testing.T) {
	for healthy := 0; healthy < 3; healthy++ {
		t.Run(fmt.Sprint(healthy), func(t *testing.T) {
			var calls [3]atomic.Int32
			var active, maxActive atomic.Int32
			handlers := make([]http.HandlerFunc, 3)
			for i := range handlers {
				i := i
				handlers[i] = func(w http.ResponseWriter, r *http.Request) {
					calls[i].Add(1)
					n := active.Add(1)
					defer active.Add(-1)
					for old := maxActive.Load(); n > old && !maxActive.CompareAndSwap(old, n); old = maxActive.Load() {
					}
					if i != healthy {
						<-r.Context().Done()
						return
					}
					select {
					case <-time.After(80 * time.Millisecond):
						io.WriteString(w, poolReady)
					case <-r.Context().Done():
					}
				}
			}
			m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, handlers...)
			started := time.Now()
			response, err := m.fetchContext(context.Background(), "sole-healthy.example")
			if err != nil || response == nil || response.Generation != "same-fill" || time.Since(started) >= 150*time.Millisecond || m.Stats().PoolAttempts != 3 || maxActive.Load() > 3 {
				t.Fatalf("solehealthy=%d err=%v elapsed=%v max=%d", healthy, err, time.Since(started), maxActive.Load())
			}
			for i := range calls {
				if calls[i].Load() != 1 {
					t.Fatalf("not unique/omitted%d", i)
				}
				s := m.pool.endpointStats()[i]
				if i == healthy {
					if s.Successes != 1 {
						t.Fatal("healthy response lost")
					}
				} else if s.WinnerCanceled != 1 || s.Timeout+s.Transport+s.Canceled != 0 || m.pool.states[i].failures != 0 {
					t.Fatalf("owncancel penalized %d %+v", i, s)
				}
			}
			deadline := time.Now().Add(time.Second)
			for active.Load() != 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if active.Load() != 0 {
				t.Fatal("HTTP handlers leaked")
			}
			t.Logf("solehealthy%d elapsed=%s maxactive=%d unique=3", healthy, time.Since(started), maxActive.Load())
		})
	}
}

// Finite isolated offered load through the real matcher foreground workers/queue.
// The fixture semaphore models a Redis pool, not production HTTP admission.
func TestAsyncDNSPoolMax3FiniteForegroundOfferQueueAndRedisRefusal(t *testing.T) {
	for _, redisSlots := range []int{2, 1} {
		t.Run(fmt.Sprint(redisSlots), func(t *testing.T) {
			release := make(chan struct{})
			var active, maxActive, refused, lookups atomic.Int32
			var backendActive, backendMax [3]atomic.Int32
			handlers := make([]http.HandlerFunc, 3)
			for i := range handlers {
				i := i
				pool := make(chan struct{}, redisSlots)
				handlers[i] = func(w http.ResponseWriter, r *http.Request) {
					n := active.Add(1)
					defer active.Add(-1)
					for old := maxActive.Load(); n > old && !maxActive.CompareAndSwap(old, n); old = maxActive.Load() {
					}
					acquireCtx, cancel := context.WithTimeout(r.Context(), 50*time.Millisecond)
					defer cancel()
					select {
					case pool <- struct{}{}:
					case <-acquireCtx.Done():
						refused.Add(1)
						http.Error(w, "fixture unavailable", 503)
						return
					}
					defer func() { <-pool }()
					lookups.Add(1)
					n = backendActive[i].Add(1)
					defer backendActive[i].Add(-1)
					for old := backendMax[i].Load(); n > old && !backendMax[i].CompareAndSwap(old, n); old = backendMax[i].Load() {
					}
					lookupCtx, stop := context.WithTimeout(r.Context(), 100*time.Millisecond)
					defer stop()
					select {
					case <-release:
						io.WriteString(w, poolReady)
					case <-lookupCtx.Done():
						http.Error(w, "fixture unavailable", 503)
					}
				}
			}
			m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150, Workers: 2, QueueCapacity: 4, CacheCapacity: 8}, handlers...)
			m.mu.Lock()
			for i := 0; i < 32; i++ {
				m.startJob(fmt.Sprintf("load%d.example", i), time.Now())
			}
			jobs, queued, dropped := len(m.jobs), len(m.queue), m.stats.queueDrops.Load()
			m.mu.Unlock()
			if jobs > 8 || queued > 4 || dropped < 24 {
				t.Fatalf("unbounded offered load jobs=%d queued=%d refused=%d", jobs, queued, dropped)
			}
			// Only the first two workers run while backends are blocked. Stop before
			// scheduled backlog can become another offered-load round.
			deadline := time.Now().Add(time.Second)
			for active.Load() < 6 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if active.Load() != 6 {
				t.Fatal("did not observe exact2workers*3slots")
			}
			if redisSlots == 1 {
				deadline = time.Now().Add(time.Second)
				for refused.Load() == 0 && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if refused.Load() == 0 {
					t.Fatal("Redis acquire refusal was not visible")
				}
			}
			// Stop prevents any subsequent queued refresh; Close cancels/drains workers.
			closeErr := make(chan error, 1)
			go func() { closeErr <- m.Close() }()
			select {
			case err := <-closeErr:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("stop did not drain")
			}
			close(release)
			deadline = time.Now().Add(time.Second)
			for active.Load() != 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if active.Load() != 0 || maxActive.Load() > 6 {
				t.Fatalf("leak/bounds active=%d max=%d", active.Load(), maxActive.Load())
			}
			for i := range backendMax {
				if backendMax[i].Load() > int32(redisSlots) || backendActive[i].Load() != 0 {
					t.Fatal("fixture Redis pool escaped bound")
				}
			}
			var started, terminal uint64
			for _, s := range m.pool.endpointStats() {
				started += s.Started
				terminal += s.Attempts
			}
			if started != terminal || started > 6 {
				t.Fatalf("detached/reoffered requests %d/%d", started, terminal)
			}
			if samples, _ := m.pool.failureSamples.take(); len(samples) > 8 {
				t.Fatal("diagnostic overflow")
			}
			t.Logf("offer32 actualJobs%d queued%d refusedQueue%d HTTPstarted%d maxHTTP%d RedisSlots%d logicalLookups%d acquireRefusals%d terminal%d stopdrained=true", jobs, queued, dropped, started, maxActive.Load(), redisSlots, lookups.Load(), refused.Load(), terminal)
		})
	}
}

func TestAsyncDNSPoolMax3AllFailKeepsParentDeadline(t *testing.T) {
	dead := func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, dead, dead, dead)
	_, err := m.fetchContext(context.Background(), "deadline.example")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("lost configured parent deadline")
	}
	if m.Stats().PoolAttempts != 3 {
		t.Fatal("wrong boundedattempts")
	}
	samples, _ := m.pool.failureSamples.take()
	if len(samples) != 1 {
		t.Fatal("failedjobdiagnostic missing")
	}
}

func TestAsyncDNSPoolMax3ThreeValidResponsesKeepOneWinner(t *testing.T) {
	var entered, release, closed [3]chan struct{}
	for i := range entered {
		entered[i] = make(chan struct{})
		release[i] = make(chan struct{})
		closed[i] = make(chan struct{})
	}
	unused := func(w http.ResponseWriter, r *http.Request) { t.Error("escaped isolated transport") }
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, unused, unused, unused)
	var active atomic.Int32
	m.client.Transport = asyncDNSHedgeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		active.Add(1)
		defer active.Add(-1)
		i := 0
		switch r.URL.Host {
		case "100.64.0.10:8090":
			i = 0
		case "100.64.0.11:8090":
			i = 1
		case "100.64.0.12:8090":
			i = 2
		default:
			t.Fatal("unknown fixture endpoint")
		}
		close(entered[i])
		<-release[i]
		body := poolReady
		if i != 0 {
			body = fmt.Sprintf(`{"state":"ready","route":"other","ttlMillis":5000,"generation":"surplus%d"}`, i)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: &asyncDNSHedgeCloseSignal{Reader: strings.NewReader(body), closed: closed[i]}, Request: r}, nil
	})
	type result struct {
		response *asyncDNSClassifierResponse
		err      error
	}
	done := make(chan result, 1)
	go func() {
		response, err := m.fetchContext(context.Background(), "three-ready.example")
		done <- result{response, err}
	}()
	select {
	case <-entered[0]:
	case <-time.After(time.Second):
		t.Fatal("primary missing")
	}
	m.pool.mu.Lock()
	locked := true
	defer func() {
		if locked {
			m.pool.mu.Unlock()
		}
	}()
	for i := 1; i < 3; i++ {
		select {
		case <-entered[i]:
		case <-time.After(time.Second):
			t.Fatal("backup missing")
		}
	}
	close(release[0])
	select {
	case <-closed[0]:
	case <-time.After(time.Second):
		t.Fatal("primary not decoded")
	}
	deadline := time.Now().Add(time.Second)
	for m.pool.endpointStats()[0].Successes != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if m.pool.endpointStats()[0].Successes != 1 {
		t.Fatal("primary not selected")
	}
	for i := 1; i < 3; i++ {
		close(release[i])
		select {
		case <-closed[i]:
		case <-time.After(time.Second):
			t.Fatal("surplus not decoded")
		}
	}
	m.pool.mu.Unlock()
	locked = false
	select {
	case r := <-done:
		if r.err != nil || r.response == nil || r.response.Generation != "same-fill" {
			t.Fatal("surplus replaced original winner")
		}
	case <-time.After(time.Second):
		t.Fatal("not joined")
	}
	for _, s := range m.pool.endpointStats() {
		if s.Attempts != 1 || s.Successes != 1 || s.WinnerCanceled+s.OperationCanceled+s.Timeout+s.Transport+s.Canceled+s.HTTP+s.Invalid+s.Request != 0 {
			t.Fatalf("surplus misclassified %+v", s)
		}
	}
	if active.Load() != 0 || m.Stats().PoolAttempts != 3 {
		t.Fatal("detached/unbounded attempts")
	}
}

// Historical health must not cancel the sole recovered80 responder merely
// because the other two, previously failure0 members are now silently lost.
// Run first against the unchanged child policy and retain its failures before
// proposing any policy repair; this is not the production954 job correlation.
func TestAsyncDNSPoolMax3SoleRecovered80HistoricalHealth(t *testing.T) {
	for healthy := 0; healthy < 3; healthy++ {
		for _, cooledBackup := range []bool{false, true} {
			t.Run(fmt.Sprintf("healthy%d/cooledBackup%t", healthy, cooledBackup), func(t *testing.T) {
				var active, maxActive atomic.Int32
				var calls [3]atomic.Int32
				var completedHealthy atomic.Bool
				handlers := make([]http.HandlerFunc, 3)
				for i := range handlers {
					i := i
					handlers[i] = func(w http.ResponseWriter, r *http.Request) {
						calls[i].Add(1)
						n := active.Add(1)
						defer active.Add(-1)
						for old := maxActive.Load(); n > old && !maxActive.CompareAndSwap(old, n); old = maxActive.Load() {
						}
						if i != healthy {
							<-r.Context().Done()
							return
						}
						select {
						case <-time.After(80 * time.Millisecond):
							completedHealthy.Store(true)
							io.WriteString(w, poolReady)
						case <-r.Context().Done():
						}
					}
				}
				m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, handlers...)
				now := time.Now()
				until := now.Add(-time.Second)
				m.pool.next = healthy
				if cooledBackup {
					until = now.Add(time.Second)
					m.pool.next = (healthy + 1) % 3
				}
				coolPoolMember(m, healthy, 1, until)
				started := time.Now()
				response, err := m.fetchContext(context.Background(), "historical-health.example")
				elapsed := time.Since(started)
				deadline := time.Now().Add(time.Second)
				for active.Load() != 0 && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if active.Load() != 0 || maxActive.Load() > 3 {
					t.Fatal("attempt not drained/unbounded")
				}
				for i := range calls {
					if calls[i].Load() != 1 {
						t.Fatalf("endpoint%d omitted/duplicated", i)
					}
				}
				t.Logf("healthy%d cooledBackup%t elapsed%s realHealthyCompleted%t parentDeadline%t maxactive%d", healthy, cooledBackup, elapsed, completedHealthy.Load(), errors.Is(err, context.DeadlineExceeded), maxActive.Load())
				raw, discarded := m.pool.failureSamples.take()
				t.Logf("FAILED-job-scalar-samples=%v discarded=%d", raw, discarded)
				if err != nil || response == nil || response.Generation != "same-fill" || !completedHealthy.Load() || elapsed >= 150*time.Millisecond {
					t.Fatalf("historical health killed sole recovered80: healthy%d cooledBackup%t err=%v", healthy, cooledBackup, err)
				}
			})
		}
	}
}
