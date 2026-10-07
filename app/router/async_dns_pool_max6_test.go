package router

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Isolated context-aware transport: five members wait for cancellation while
// the sole member completes its real 80ms work. No production network/load.
func TestAsyncDNSPoolMax6EachSoleHealthy80HistoricalHealth(t *testing.T) {
	for _, history := range []string{"unknown", "expired", "all-cooled"} {
		for healthy := range 6 {
			t.Run(fmt.Sprintf("%s/healthy%d", history, healthy), func(t *testing.T) {
				unused := func(w http.ResponseWriter, r *http.Request) { t.Error("escaped isolated transport") }
				m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, unused, unused, unused, unused, unused, unused)
				if history == "expired" {
					coolPoolMember(m, healthy, 6, time.Now().Add(-time.Second))
				} else if history == "all-cooled" {
					for i := range 6 {
						coolPoolMember(m, i, uint8(i+1), time.Now().Add(time.Second))
					}
				}
				var calls [6]atomic.Int32
				var active, maxActive atomic.Int32
				deadlines := make(chan time.Time, 6)
				bodyClosed := make(chan struct{})
				m.client.Transport = asyncDNSHedgeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					i, err := strconv.Atoi(strings.TrimPrefix(r.URL.Hostname(), "100.64.0."))
					if err != nil || i < 10 || i > 15 {
						return nil, errors.New("outside isolated pool")
					}
					i -= 10
					calls[i].Add(1)
					n := active.Add(1)
					defer active.Add(-1)
					for old := maxActive.Load(); n > old && !maxActive.CompareAndSwap(old, n); old = maxActive.Load() {
					}
					d, ok := r.Context().Deadline()
					if !ok {
						t.Error("missing parent deadline")
					}
					deadlines <- d
					if i != healthy {
						<-r.Context().Done()
						return nil, r.Context().Err()
					}
					timer := time.NewTimer(80 * time.Millisecond)
					defer timer.Stop()
					select {
					case <-timer.C:
						body := fmt.Sprintf(`{"state":"ready","route":"ru","ttlMillis":5000,"generation":"sole%d"}`, healthy)
						return &http.Response{StatusCode: 200, Header: make(http.Header), Body: &asyncDNSHedgeCloseSignal{Reader: strings.NewReader(body), closed: bodyClosed}, Request: r}, nil
					case <-r.Context().Done():
						return nil, r.Context().Err()
					}
				})
				started := time.Now()
				response, err := m.fetchContext(context.Background(), "isolated.example")
				elapsed := time.Since(started)
				if err != nil || response == nil || response.Generation != fmt.Sprintf("sole%d", healthy) || elapsed >= 150*time.Millisecond || active.Load() != 0 || maxActive.Load() != 6 || m.Stats().PoolAttempts != 6 {
					t.Fatalf("sole%d err=%v elapsed=%s active=%d max=%d stats=%+v", healthy, err, elapsed, active.Load(), maxActive.Load(), m.Stats())
				}
				select {
				case <-bodyClosed:
				default:
					t.Fatal("winner response body not closed")
				}
				parent := <-deadlines
				for range 5 {
					if d := <-deadlines; !d.Equal(parent) {
						t.Fatal("attempt shortened parent budget")
					}
				}
				if parent.Sub(started) < 149*time.Millisecond || parent.Sub(started) > 151*time.Millisecond {
					t.Fatal("configured parent changed")
				}
				for i, s := range m.pool.endpointStats() {
					if calls[i].Load() != 1 || s.Attempts != 1 || s.Started != s.Attempts || s.Timeout+s.Transport+s.HTTP+s.Canceled+s.OperationCanceled != 0 || s.CooldownSkips != 0 {
						t.Fatalf("omitted/repeated/unaccounted member%d %+v", i, s)
					}
					if i == healthy {
						if s.Successes != 1 || s.WinnerCanceled != 0 || m.pool.states[i].failures != 0 {
							t.Fatal("sole response/health lost")
						}
					} else if s.WinnerCanceled != 1 {
						t.Fatal("winner cancellation lost")
					}
				}
				t.Logf("history=%s sole=%d elapsed=%s maxActive=6 unique=6 terminal=6 drained=true", history, healthy, elapsed)
			})
		}
	}
}

func TestAsyncDNSPoolMax6AllSilentParentAndCallerCancellation(t *testing.T) {
	for _, caller := range []bool{false, true} {
		t.Run(fmt.Sprint(caller), func(t *testing.T) {
			unused := func(w http.ResponseWriter, r *http.Request) { t.Error("escaped isolated transport") }
			m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, unused, unused, unused, unused, unused, unused)
			var active, calls atomic.Int32
			startedAll := make(chan struct{}, 6)
			m.client.Transport = asyncDNSHedgeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				active.Add(1)
				defer active.Add(-1)
				startedAll <- struct{}{}
				<-r.Context().Done()
				return nil, r.Context().Err()
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if caller {
				go func() {
					for range 6 {
						<-startedAll
					}
					cancel()
				}()
			}
			_, err := m.fetchContext(ctx, "isolated.example")
			expected := context.DeadlineExceeded
			if caller {
				expected = context.Canceled
			}
			if !errors.Is(err, expected) || active.Load() != 0 || calls.Load() != 6 {
				t.Fatalf("not bounded/drained: %v active%d calls%d", err, active.Load(), calls.Load())
			}
			raw, discarded := m.pool.failureSamples.take()
			if len(raw) != 1 || discarded != 0 || len(raw[0]) > 4096 {
				t.Fatal("max6 diagnostic lost/oversized")
			}
			var sample asyncDNSPoolFailureSample
			if err := json.Unmarshal([]byte(raw[0]), &sample); err != nil {
				t.Fatal(err)
			}
			if sample.MaxConcurrent != 6 || len(sample.Attempts) != 6 || !sample.valid() {
				t.Fatal("max6 diagnostic not supported")
			}
			sample.MaxConcurrent = 7
			if sample.valid() {
				t.Fatal("diagnostic accepted unbounded concurrency")
			}
			for _, s := range m.pool.endpointStats() {
				if s.Attempts != 1 || s.Started != s.Attempts || s.WinnerCanceled != 0 || caller && s.Canceled != 1 || !caller && s.Timeout != 1 {
					t.Fatalf("terminal partition wrong %+v", s)
				}
			}
		})
	}
}

func TestAsyncDNSPoolMax6FastAndAuthSingleAttempt(t *testing.T) {
	for _, auth := range []bool{false, true} {
		t.Run(fmt.Sprint(auth), func(t *testing.T) {
			var calls atomic.Int32
			handler := func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if auth {
					w.WriteHeader(http.StatusUnauthorized)
				} else {
					io.WriteString(w, poolReady)
				}
			}
			m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, handler, handler, handler, handler, handler, handler)
			r, err := m.fetchContext(context.Background(), "isolated.example")
			if calls.Load() != 1 || m.Stats().PoolAttempts != 1 || auth && err == nil || !auth && (err != nil || r == nil) {
				t.Fatal("fast/auth fanned out")
			}
		})
	}
}
