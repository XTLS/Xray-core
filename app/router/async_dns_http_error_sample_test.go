package router

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAsyncDNSHTTPErrorSamplesCapPrivacyAndDrain(t *testing.T) {
	c := new(asyncDNSHTTPTraceCounters)
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr := &asyncDNSHTTPAttemptTrace{counters: c, started: time.Now()}
			tr.finish(&net.OpError{Op: "dial", Err: errors.New("secret-token http://private.example")})
		}()
	}
	wg.Wait()
	samples, discarded := c.takeErrorSamples()
	if len(samples) != 4 || discarded != 36 {
		t.Fatalf("cap %d/%d", len(samples), discarded)
	}
	for _, s := range samples {
		if s.Outcome != "transport" || s.NetOp != "dial" || s.AcquireMicros != -1 || s.FirstByteAtMicros != -1 || s.TCPFailure.RTTMicros != -1 {
			t.Fatalf("missing/outcome %+v", s)
		}
		line := s.logLine(1, 0)
		for _, bad := range []string{"secret", "private.example", "http://", "dial tcp"} {
			if strings.Contains(line, bad) {
				t.Fatal("privacy leak")
			}
		}
	}
	if samples, n := c.takeErrorSamples(); len(samples) != 0 || n != 0 {
		t.Fatal("not drained")
	}
}

func TestAsyncDNSHTTPErrorSamplesDelayedHeadersBodyAndTerminal(t *testing.T) {
	for _, kind := range []string{"headers", "body", "auth", "pending"} {
		t.Run(kind, func(t *testing.T) {
			m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 40}, func(w http.ResponseWriter, r *http.Request) {
				switch kind {
				case "headers":
					<-r.Context().Done()
				case "body":
					w.Header().Set("Content-Length", "100")
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				case "auth":
					w.WriteHeader(401)
				case "pending":
					io.WriteString(w, `{"status":"pending","retryAfterMillis":100}`)
				}
			}, func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected fanout") })
			_, err := m.fetch("private.example")
			samples, _ := m.pool.states[0].metrics.trace.takeErrorSamples()
			if kind == "pending" {
				if len(samples) != 0 || err != nil {
					t.Fatal("pending changed")
				}
				return
			}
			if len(samples) != 1 {
				t.Fatalf("samples=%d", len(samples))
			}
			s := samples[0]
			if s.AcquireMicros < 0 || s.WroteAtMicros < 0 || s.EndMicros < s.WroteAtMicros {
				t.Fatalf("timing %+v", s)
			}
			if kind == "headers" {
				if !errors.Is(err, context.DeadlineExceeded) || s.FirstByteAtMicros != -1 || s.Phase != asyncDNSHTTPHeaders {
					t.Fatalf("headers %+v", s)
				}
			}
			if kind == "body" {
				if !errors.Is(err, context.DeadlineExceeded) || s.FirstByteAtMicros < 0 || s.Phase != asyncDNSHTTPBody {
					t.Fatalf("body %+v", s)
				}
			}
			if kind == "auth" {
				if s.Outcome != "http" || s.FirstByteAtMicros < 0 {
					t.Fatalf("auth %+v", s)
				}
			}
		})
	}
}

func TestAsyncDNSHTTPErrorSamplesCancelReuseAndLateCallbacks(t *testing.T) {
	c := new(asyncDNSHTTPTraceCounters)
	tr := &asyncDNSHTTPAttemptTrace{counters: c, started: time.Now()}
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://private.example", nil)
	req = tr.request(req)
	trace := httptrace.ContextClientTrace(req.Context())
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	trace.GetConn("secret")
	trace.GotConn(httptrace.GotConnInfo{Conn: left, Reused: true})
	trace.WroteRequest(httptrace.WroteRequestInfo{})
	tr.finish(context.Canceled)
	// Late callbacks are harmless even under concurrent transport completion.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			trace.GotFirstResponseByte()
			trace.WroteRequest(httptrace.WroteRequestInfo{})
		}()
	}
	wg.Wait()
	samples, _ := c.takeErrorSamples()
	if len(samples) != 1 {
		t.Fatal("sample missing")
	}
	s := samples[0]
	if s.Outcome != "cancel" || !s.Reused || s.FirstByteAtMicros != -1 || s.TCPAcquire.Status != "unsupported" {
		t.Fatalf("cancel/reuse %+v", s)
	}
}

func TestAsyncDNSTCPInfoUnavailable(t *testing.T) {
	s := asyncDNSReadTCPInfo(nil)
	if s.Status == "available" || s.TotalRetrans != -1 || s.RTTMicros != -1 {
		t.Fatalf("unavailable %+v", s)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	client.Close()
	s = asyncDNSReadTCPInfo(client)
	if s.Status == "available" || s.TotalRetrans != -1 {
		t.Fatalf("closed %+v", s)
	}
}

func TestAsyncDNSTCPInfoPairedRetransDelta(t *testing.T) {
	acquired := asyncDNSTCPInfo{Status: "available", TotalRetrans: 7}
	failed := asyncDNSTCPInfo{Status: "available", TotalRetrans: 10}
	if delta := asyncDNSTCPRetransDelta(acquired, failed); delta != 3 {
		t.Fatalf("positive paired delta=%d", delta)
	}
	if delta := asyncDNSTCPRetransDelta(acquired, acquired); delta != 0 {
		t.Fatalf("paired unchanged delta=%d", delta)
	}
	for _, other := range []asyncDNSTCPInfo{asyncDNSTCPUnavailable("unavailable"), asyncDNSTCPUnavailable("unsupported"), {Status: "available", TotalRetrans: 6}} {
		if asyncDNSTCPRetransDelta(acquired, other) != -1 || asyncDNSTCPRetransDelta(other, failed) != -1 && other.Status != "available" {
			t.Fatal("unavailable/reset must not imply zero retransmissions")
		}
	}
}
