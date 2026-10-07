package router

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAsyncDNSPoolHedgeFastWinnerSingleAttempt(t *testing.T) {
	var calls atomic.Int32
	fast := func(w http.ResponseWriter, r *http.Request) { calls.Add(1); io.WriteString(w, poolReady) }
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, fast, fast, fast)
	response, err := m.fetchContext(context.Background(), "fast.example")
	if err != nil || response.Route != "ru" || calls.Load() != 1 || m.Stats().PoolAttempts != 1 {
		t.Fatalf("fast winner fanned out: %v %d", err, calls.Load())
	}
}

func TestAsyncDNSPoolHedgeOriginal80msWinnerAndDrain(t *testing.T) {
	var calls, active atomic.Int32
	slow := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			active.Add(1)
			defer active.Add(-1)
			select {
			case <-time.After(80 * time.Millisecond):
				io.WriteString(w, body)
			case <-r.Context().Done():
			}
		}
	}
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, slow(poolReady), slow(`{"state":"ready","route":"other","ttlMillis":5000,"generation":"alternate"}`), slow(poolReady))
	started := time.Now()
	response, err := m.fetchContext(context.Background(), "healthy.example")
	if err != nil || response.Route != "ru" || response.Generation != "same-fill" || calls.Load() != 2 || time.Since(started) >= 150*time.Millisecond {
		t.Fatalf("healthy80 lost: %v calls=%d", err, calls.Load())
	}
	stats := m.pool.endpointStats()
	if stats[0].Successes != 1 || stats[1].WinnerCanceled != 1 || stats[1].Canceled != 0 || stats[1].Timeout != 0 || stats[2].Started != 0 {
		t.Fatalf("wrong winner/loser: %+v", stats)
	}
	if m.pool.states[1].failures != 0 {
		t.Fatal("winner cancellation penalized loser")
	}
	deadline := time.Now().Add(time.Second)
	for active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active.Load() != 0 {
		t.Fatal("HTTP handler/socket not drained")
	}
}

func TestAsyncDNSPoolHedgeAnySelectedPrimarySilent(t *testing.T) {
	for selected := 0; selected < 3; selected++ {
		t.Run(string(rune('0'+selected)), func(t *testing.T) {
			var active, maxActive atomic.Int32
			handlers := make([]http.HandlerFunc, 3)
			for i := range handlers {
				i := i
				handlers[i] = func(w http.ResponseWriter, r *http.Request) {
					n := active.Add(1)
					defer active.Add(-1)
					for old := maxActive.Load(); n > old && !maxActive.CompareAndSwap(old, n); old = maxActive.Load() {
					}
					if i == selected {
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
			m.pool.next = selected
			started := time.Now()
			response, err := m.fetchContext(context.Background(), "silent.example")
			if err != nil || response.Route != "ru" || time.Since(started) >= 150*time.Millisecond || m.Stats().PoolAttempts != 2 || maxActive.Load() > 2 {
				t.Fatalf("silent primary not recovered: %v elapsed=%v attempts=%d max=%d", err, time.Since(started), m.Stats().PoolAttempts, maxActive.Load())
			}
			if stats := m.pool.endpointStats(); stats[selected].WinnerCanceled != 1 || stats[selected].Timeout != 0 {
				t.Fatalf("silent pending cancellation mislabeled: %+v", stats)
			}
		})
	}
}

func TestAsyncDNSPoolHedgeAllSilentBoundedAndCallerCancel(t *testing.T) {
	for _, callerCancel := range []bool{false, true} {
		t.Run(map[bool]string{false: "deadline", true: "caller"}[callerCancel], func(t *testing.T) {
			var calls, active, maxActive atomic.Int32
			handler := func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				n := active.Add(1)
				defer active.Add(-1)
				for old := maxActive.Load(); n > old && !maxActive.CompareAndSwap(old, n); old = maxActive.Load() {
				}
				<-r.Context().Done()
			}
			m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, handler, handler, handler)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if callerCancel {
				time.AfterFunc(75*time.Millisecond, cancel)
			}
			started := time.Now()
			_, err := m.fetchContext(ctx, "down.example")
			expected := context.DeadlineExceeded
			if callerCancel {
				expected = context.Canceled
			}
			if !errors.Is(err, expected) || time.Since(started) > 230*time.Millisecond || calls.Load() != 2 || maxActive.Load() > 2 {
				t.Fatalf("failed bound/drain: %v %v %d", err, time.Since(started), calls.Load())
			}
			stats := m.pool.endpointStats()
			for i := 0; i < 2; i++ {
				if stats[i].WinnerCanceled != 0 || stats[i].Attempts != 1 || callerCancel && (stats[i].Canceled != 1 || m.pool.states[i].failures != 0) || !callerCancel && (stats[i].Timeout != 1 || m.pool.states[i].failures != 1) {
					t.Fatalf("error classification wrong: %+v", stats)
				}
			}
			deadline := time.Now().Add(time.Second)
			for active.Load() != 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if active.Load() != 0 {
				t.Fatal("server request leaked")
			}
		})
	}
}

func TestAsyncDNSPoolHedgeRecoveredHTTPFailureVisible(t *testing.T) {
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150},
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) },
		func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, poolReady) },
		func(w http.ResponseWriter, r *http.Request) { t.Error("unused third endpoint called") },
	)
	response, err := m.fetchContext(context.Background(), "recover.example")
	stats := m.pool.endpointStats()
	if err != nil || response.Route != "ru" || stats[0].HTTP503 != 1 || stats[0].HTTP != 1 || stats[1].Successes != 1 || m.pool.states[0].failures != 1 || m.Stats().PoolAttempts != 2 {
		t.Fatalf("recovered real failure hidden: %v %+v", err, stats)
	}
}

func TestAsyncDNSPoolHedgeTerminalAuthDrainsAlternate(t *testing.T) {
	var active atomic.Int32
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150},
		func(w http.ResponseWriter, r *http.Request) {
			active.Add(1)
			defer active.Add(-1)
			time.Sleep(80 * time.Millisecond)
			w.WriteHeader(401)
		},
		func(w http.ResponseWriter, r *http.Request) {
			active.Add(1)
			defer active.Add(-1)
			<-r.Context().Done()
		},
		func(w http.ResponseWriter, r *http.Request) { t.Error("terminal auth fanned out to third") },
	)
	_, err := m.fetchContext(context.Background(), "auth.example")
	stats := m.pool.endpointStats()
	if err == nil || stats[0].HTTP401 != 1 || stats[1].OperationCanceled != 1 || stats[1].Transport != 0 || stats[1].WinnerCanceled != 0 || m.pool.states[1].failures != 0 {
		t.Fatalf("terminal cancellation hidden/penalized: %v %+v", err, stats)
	}
	deadline := time.Now().Add(time.Second)
	for active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active.Load() != 0 {
		t.Fatal("auth stop leaked request")
	}
}

type asyncDNSHedgeTrackedConn struct {
	net.Conn
	once   sync.Once
	active *atomic.Int32
}

func (c *asyncDNSHedgeTrackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.active.Add(-1) })
	return err
}

func TestAsyncDNSPoolHedgeRepeatedHTTPConnectionsDrained(t *testing.T) {
	var serverActive, connections atomic.Int32
	handlers := make([]http.HandlerFunc, 3)
	for i := range handlers {
		handlers[i] = func(w http.ResponseWriter, r *http.Request) {
			serverActive.Add(1)
			defer serverActive.Add(-1)
			select {
			case <-time.After(80 * time.Millisecond):
				io.WriteString(w, poolReady)
			case <-r.Context().Done():
			}
		}
	}
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, handlers...)
	transport := m.client.Transport.(*http.Transport)
	dial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		connections.Add(1)
		return &asyncDNSHedgeTrackedConn{Conn: c, active: &connections}, nil
	}
	for range 12 {
		response, err := m.fetchContext(context.Background(), "drain.example")
		if err != nil || response.Route != "ru" {
			t.Fatalf("repeated request failed: %v", err)
		}
		// Transport terminal counters are recorded by the coordinator before return.
		var started, completed, success, canceled uint64
		for _, s := range m.pool.endpointStats() {
			started += s.Started
			completed += s.Attempts
			success += s.Successes
			canceled += s.WinnerCanceled
			if s.Transport+s.Timeout+s.Canceled+s.HTTP+s.Invalid+s.Request+s.OperationCanceled != 0 {
				t.Fatalf("winner cancel hidden as real error: %+v", s)
			}
		}
		if started != completed || completed != success+canceled || success*2 != completed {
			t.Fatalf("unjoined attempt escaped conservation: started=%d completed=%d success=%d cancel=%d", started, completed, success, canceled)
		}
	}
	m.client.CloseIdleConnections()
	deadline := time.Now().Add(time.Second)
	for (serverActive.Load() != 0 || connections.Load() != 0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if serverActive.Load() != 0 || connections.Load() != 0 {
		t.Fatalf("request goroutine/socket leaked: handlers=%d sockets=%d", serverActive.Load(), connections.Load())
	}
}

type asyncDNSHedgeRoundTripFunc func(*http.Request) (*http.Response, error)

func (f asyncDNSHedgeRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type asyncDNSHedgeCloseSignal struct {
	io.Reader
	closed chan struct{}
}

func (b *asyncDNSHedgeCloseSignal) Close() error { close(b.closed); return nil }

func TestAsyncDNSPoolHedgeBothValidResponsesKeepOriginalWinner(t *testing.T) {
	firstEntered, secondEntered := make(chan struct{}), make(chan struct{})
	firstRelease, secondRelease := make(chan struct{}), make(chan struct{})
	firstClosed, secondClosed := make(chan struct{}), make(chan struct{})
	var active atomic.Int32
	unused := func(w http.ResponseWriter, r *http.Request) { t.Error("fixture escaped controlled transport") }
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, unused, unused, unused)
	m.client.Transport = asyncDNSHedgeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		active.Add(1)
		defer active.Add(-1)
		var body string
		var closed chan struct{}
		switch r.URL.Host {
		case "100.64.0.10:8090":
			close(firstEntered)
			<-firstRelease
			body = poolReady
			closed = firstClosed
		case "100.64.0.11:8090":
			close(secondEntered)
			<-secondRelease
			body = `{"state":"ready","route":"other","ttlMillis":5000,"generation":"surplus"}`
			closed = secondClosed
		default:
			return nil, errors.New("unexpected third attempt")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: &asyncDNSHedgeCloseSignal{Reader: strings.NewReader(body), closed: closed}, Request: r}, nil
	})
	type outcome struct {
		response *asyncDNSClassifierResponse
		err      error
	}
	done := make(chan outcome, 1)
	go func() {
		response, err := m.fetchContext(context.Background(), "both-ready.example")
		done <- outcome{response, err}
	}()
	select {
	case <-firstEntered:
	case <-time.After(time.Second):
		t.Fatal("first did not start")
	}
	// Candidates/start are already captured. The pool mutex now blocks only
	// record(), AFTER the coordinator selected and observed the original response.
	m.pool.mu.Lock()
	locked := true
	defer func() {
		if locked {
			m.pool.mu.Unlock()
		}
	}()
	select {
	case <-secondEntered:
	case <-time.After(time.Second):
		t.Fatal("hedge did not start")
	}
	close(firstRelease)
	select {
	case <-firstClosed:
	case <-time.After(time.Second):
		t.Fatal("original body not decoded/closed")
	}
	deadline := time.Now().Add(time.Second)
	for m.pool.endpointStats()[0].Successes != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if m.pool.endpointStats()[0].Successes != 1 {
		t.Fatal("original response not selected before surplus release")
	}
	close(secondRelease)
	select {
	case <-secondClosed:
	case <-time.After(time.Second):
		t.Fatal("surplus body not decoded/closed")
	}
	m.pool.mu.Unlock()
	locked = false
	var result outcome
	select {
	case result = <-done:
	case <-time.After(time.Second):
		t.Fatal("attempt goroutines not joined")
	}
	if result.err != nil || result.response == nil || result.response.Route != "ru" || result.response.Generation != "same-fill" {
		t.Fatalf("surplus replaced original winner: %+v", result)
	}
	stats := m.pool.endpointStats()
	for i := 0; i < 2; i++ {
		if stats[i].Started != 1 || stats[i].Attempts != 1 || stats[i].Successes != 1 || stats[i].WinnerCanceled+stats[i].OperationCanceled+stats[i].Canceled+stats[i].Timeout+stats[i].Transport+stats[i].HTTP+stats[i].Invalid+stats[i].Request != 0 {
			t.Fatalf("completed success fabricated as cancellation/error: %+v", stats)
		}
	}
	if stats[2].Started != 0 || active.Load() != 0 || m.Stats().PoolAttempts != 2 {
		t.Fatalf("surplus escaped bounds/join: %+v active=%d", stats, active.Load())
	}
}

func TestAsyncDNSPoolHedgeDeadlineAndReadyResultRace(t *testing.T) {
	// Both ready responses are released by deadline, so the coordinator's
	// result and ctx.Done arms can race. As with the former sequential transport,
	// either a valid result or deadline error is allowed at this exact boundary;
	// already decoded endpoint successes must never be relabeled as timeouts.
	for range 8 {
		var active atomic.Int32
		unused := func(w http.ResponseWriter, r *http.Request) { t.Error("fixture escaped controlled transport") }
		m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 75}, unused, unused, unused)
		m.client.Transport = asyncDNSHedgeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			active.Add(1)
			defer active.Add(-1)
			<-r.Context().Done()
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(poolReady)), Request: r}, nil
		})
		response, err := m.fetchContext(context.Background(), "deadline-ready.example")
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("race produced unrelated error: %v", err)
		}
		if err == nil && (response == nil || response.Route != "ru" || response.Generation != "same-fill") {
			t.Fatalf("race lost valid result: %+v", response)
		}
		if err != nil && response != nil {
			t.Fatal("deadline returned conflicting response")
		}
		stats := m.pool.endpointStats()
		for i := 0; i < 2; i++ {
			if stats[i].Attempts != 1 || stats[i].Successes != 1 || stats[i].WinnerCanceled+stats[i].OperationCanceled+stats[i].Canceled+stats[i].Timeout+stats[i].Transport != 0 {
				t.Fatalf("ready race hid successes or invented failure: %+v", stats)
			}
		}
		if m.Stats().PoolAttempts != 2 || stats[2].Started != 0 || active.Load() != 0 {
			t.Fatalf("deadline race detached attempt: %+v", stats)
		}
	}
}
