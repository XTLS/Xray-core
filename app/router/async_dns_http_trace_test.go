package router

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAsyncDNSHTTPTraceDelayedHeadersAndBody(t *testing.T) {
	for _, body := range []bool{false, true} {
		t.Run(map[bool]string{false: "headers", true: "body"}[body], func(t *testing.T) {
			m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 40}, func(w http.ResponseWriter, r *http.Request) {
				if body {
					w.Header().Set("Content-Length", "100")
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
				}
				<-r.Context().Done()
			}, func(w http.ResponseWriter, r *http.Request) { t.Error("parent deadline retried") })
			start := time.Now()
			_, err := m.fetch("private.example")
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("deadline missing: %T", err)
			}
			if time.Since(start) > 200*time.Millisecond {
				t.Fatal("budget changed")
			}
			s := m.pool.endpointStats()
			phase := asyncDNSHTTPHeaders
			if body {
				phase = asyncDNSHTTPBody
			}
			expectedFirstByte := uint64(0)
			if body {
				expectedFirstByte = 1
			}
			if s[0].Trace.FirstByte != expectedFirstByte || s[0].Trace.Phases[phase] != 1 || s[0].Timeout != 1 || s[1].Attempts != 0 {
				t.Fatalf("phase/outcome mismatch: %+v", s)
			}
		})
	}
}

func TestAsyncDNSHTTPTraceRefusedConnectionAndPrivacy(t *testing.T) {
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, func(w http.ResponseWriter, r *http.Request) { t.Error("refused dial reached handler") }, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, poolReady) })
	tr := m.client.Transport.(*http.Transport)
	dial := tr.DialContext
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "100.64.0.10:8090" {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("secret-token private.example")}
		}
		return dial(ctx, network, address)
	}
	if _, err := m.fetch("private.example"); err != nil {
		t.Fatal(err)
	}
	s := m.pool.endpointStats()
	if s[0].Trace.Phases[asyncDNSHTTPAcquire] != 1 || s[0].Trace.NetDial != 1 || s[0].Transport != 1 || s[1].Successes != 1 {
		t.Fatalf("refusal changed: %+v", s)
	}
	for i, x := range s {
		line := x.logLine(1, i)
		for _, bad := range []string{"secret", "private.example", "100.64", "http://", "dial tcp"} {
			if strings.Contains(line, bad) {
				t.Fatal("private text exposed")
			}
		}
	}
}

func TestAsyncDNSHTTPTraceReusedConnection(t *testing.T) {
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, poolReady) }, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, poolReady) })
	for i := 0; i < 3; i++ {
		if _, err := m.fetch("valid.example"); err != nil {
			t.Fatal(err)
		}
	}
	s := m.pool.endpointStats()
	if s[0].Trace.NewConn != 1 || s[0].Trace.ReusedConn != 1 || s[0].Trace.Phases[asyncDNSHTTPComplete] != 2 || s[0].Trace.AcquireLE150 != 2 {
		t.Fatalf("connection stats changed: %+v", s)
	}
}

func TestAsyncDNSHTTPTraceParentCancelNoHealthPenalty(t *testing.T) {
	entered := make(chan struct{})
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() }, func(w http.ResponseWriter, r *http.Request) { t.Error("cancel retried") })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := m.fetchContext(ctx, "valid.example"); done <- err }()
	<-entered
	cancel()
	if !errors.Is(<-done, context.Canceled) {
		t.Fatal("external cancel changed")
	}
	s := m.pool.endpointStats()
	if s[0].Canceled != 1 || s[0].Trace.Phases[asyncDNSHTTPHeaders] != 1 || s[1].Attempts != 0 || m.pool.states[0].failures != 0 {
		t.Fatalf("cancel semantics changed: %+v", s)
	}
}

func TestAsyncDNSHTTPTraceTerminalAuthPendingAndCooldown(t *testing.T) {
	for _, status := range []int{401, 429, 200} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Uint64
			m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(status)
				if status == 200 {
					io.WriteString(w, `{"state":"pending","retryAfterMillis":5000}`)
				}
			}, func(w http.ResponseWriter, r *http.Request) { t.Error("terminal result retried") })
			_, err := m.fetch("valid.example")
			if (err == nil) != (status == 200) {
				t.Fatal("terminal behavior changed")
			}
			s := m.pool.endpointStats()
			if calls.Load() != 1 || s[0].Attempts != 1 || s[1].Attempts != 0 {
				t.Fatalf("fanout changed: %+v", s)
			}
			phase := asyncDNSHTTPFirstByte
			if status == 200 {
				phase = asyncDNSHTTPComplete
				if s[0].Pending != 1 {
					t.Fatal("pending changed")
				}
			}
			if s[0].Trace.Phases[phase] != 1 {
				t.Fatalf("terminal phase missing: %+v", s)
			}
			m.pool.mu.Lock()
			for i := range m.pool.states {
				m.pool.states[i].cooldownUntil = time.Now().Add(time.Hour)
			}
			m.pool.mu.Unlock()
			_, err = m.fetch("next.example")
			if err == nil || m.Stats().PoolSyntheticCooldown != 1 || calls.Load() != 1 {
				t.Fatal("cooldown changed behavior")
			}
			after := m.pool.endpointStats()
			if after[0].Attempts != 1 || after[1].Attempts != 0 {
				t.Fatal("synthetic cooldown counted as HTTP")
			}
		})
	}
}

func TestAsyncDNSHTTPTracePartialHeadersAfterFirstByte(t *testing.T) {
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 40}, func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nX-Partial:")
		time.Sleep(80 * time.Millisecond)
	}, func(w http.ResponseWriter, r *http.Request) { t.Error("parent deadline retried") })
	_, err := m.fetch("private.example")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline missing: %T", err)
	}
	s := m.pool.endpointStats()
	if s[0].Timeout != 1 || s[0].Trace.FirstByte != 1 || s[0].Trace.Phases[asyncDNSHTTPFirstByte] != 1 || s[1].Attempts != 0 {
		t.Fatalf("partial headers indistinguishable: %+v", s)
	}
}
