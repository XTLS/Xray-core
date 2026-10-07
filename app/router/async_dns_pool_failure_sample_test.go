package router

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAsyncDNSPoolFailureSamplePrivacyOverflowAndEnums(t *testing.T) {
	sample := asyncDNSPoolFailureSample{Budget: 150000, Elapsed: 150100, MaxConcurrent: 2, Terminal: "deadline", Deadline: true}
	for i := 0; i < 6; i++ {
		sample.Candidates = append(sample.Candidates, asyncDNSPoolCandidateSample{Index: i, Ordinal: i, KnownFailed: true, Selected: true, Failures: 6, Cooldown: 5000000})
		sample.Attempts = append(sample.Attempts, asyncDNSPoolAttemptSample{Index: i, Ordinal: i, Launch: 50000, Remaining: 100000, ChildBudget: 50000, TerminalOffset: 150000, Phase: asyncDNSHTTPHeaders, Acquire: 123, Wrote: 456, FirstByte: -1, Terminal: "deadline", Cause: "deadline"})
	}
	var b asyncDNSPoolFailureBuffer
	var wg sync.WaitGroup
	for i := 0; i < 9; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); b.add(sample) }()
	}
	wg.Wait()
	samples, discarded := b.take()
	if len(samples) != 8 || discarded != 1 {
		t.Fatalf("overflow %d/%d", len(samples), discarded)
	}
	for _, s := range samples {
		if len(s) > 4096 {
			t.Fatal("unbounded sample")
		}
		for _, forbidden := range []string{"http://", "example", "Bearer", "Domain", "Endpoint", "token", "error text"} {
			if strings.Contains(s, forbidden) {
				t.Fatalf("private field %s", forbidden)
			}
		}
	}
	if samples, d := b.take(); len(samples) != 0 || d != 0 {
		t.Fatal("period did not drain")
	}
	sample.Attempts[0].Terminal = "private error text"
	b.add(sample)
	if samples, d := b.take(); len(samples) != 0 || d != 1 {
		t.Fatal("unsupported terminal retained")
	}
	sample.Attempts[0].Terminal = "deadline"
	sample.Attempts[0].Cause = "secret"
	b.add(sample)
	if samples, d := b.take(); len(samples) != 0 || d != 1 {
		t.Fatal("unsupported cause retained")
	}
}

func TestAsyncDNSPoolSuccessfulJobsHaveNoFailureSamples(t *testing.T) {
	fast := func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, poolReady) }
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, fast, fast, fast)
	if _, err := m.fetchContext(context.Background(), "private-domain.example"); err != nil {
		t.Fatal(err)
	}
	if s, d := m.pool.failureSamples.take(); len(s) != 0 || d != 0 {
		t.Fatal("success retained")
	}
}

func TestAsyncDNSPoolFailureSampleAuthAndDrain(t *testing.T) {
	deny := func(w http.ResponseWriter, r *http.Request) { http.Error(w, "secret body", 401) }
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, deny, deny, deny)
	if _, err := m.fetchContext(context.Background(), "secret.example"); err == nil {
		t.Fatal("expected terminal")
	}
	raw, d := m.pool.failureSamples.take()
	if len(raw) != 1 || d != 0 {
		t.Fatalf("samples=%d/%d", len(raw), d)
	}
	var s asyncDNSPoolFailureSample
	if err := json.Unmarshal([]byte(raw[0]), &s); err != nil {
		t.Fatal(err)
	}
	if s.Terminal != "http_auth" || len(s.Attempts) != 1 || s.Attempts[0].Terminal != "http_auth" || s.Attempts[0].Phase != asyncDNSHTTPFirstByte || s.MaxConcurrent != 1 {
		t.Fatalf("wrong job %+v", s)
	}
	if s.Attempts[0].Acquire < 0 || s.Attempts[0].Wrote < 0 {
		t.Fatal("lost HTTP timeline")
	}
}

func TestAsyncDNSPoolFailureSampleCancellationTaxonomy(t *testing.T) {
	for _, c := range []struct {
		err, cause error
		want       string
	}{{context.Canceled, asyncDNSPoolWinnerCancel, "winner_cancel"}, {context.Canceled, asyncDNSPoolTerminalCancel, "terminal_cancel"}, {context.Canceled, context.Canceled, "caller_cancel"}, {context.DeadlineExceeded, context.DeadlineExceeded, "deadline"}, {errors.New("SECRET"), nil, "transport"}} {
		if got := asyncDNSPoolDiagnosticOutcome(nil, c.err, c.cause); got != c.want {
			t.Fatalf("got %s want %s", got, c.want)
		}
	}
}

func TestAsyncDNSPoolFailureSampleDrainsBothCallerCanceledAttempts(t *testing.T) {
	started := make(chan struct{}, 2)
	ended := make(chan struct{}, 2)
	silent := func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-r.Context().Done()
		ended <- struct{}{}
	}
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, silent, silent, silent)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := m.fetchContext(ctx, "PRIVATE.example"); done <- err }()
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("hedge did not start")
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("wrong caller cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("job did not drain")
	}
	raw, d := m.pool.failureSamples.take()
	if len(raw) != 1 || d != 0 {
		t.Fatal("job not retained after drain")
	}
	var sample asyncDNSPoolFailureSample
	if err := json.Unmarshal([]byte(raw[0]), &sample); err != nil {
		t.Fatal(err)
	}
	if sample.Terminal != "caller_cancel" || sample.MaxConcurrent != 2 || len(sample.Attempts) != 2 || sample.Deadline {
		t.Fatalf("bad job %+v", sample)
	}
	for _, a := range sample.Attempts {
		if a.Terminal != "caller_cancel" || a.Cause != "caller" || a.Phase != asyncDNSHTTPHeaders {
			t.Fatalf("bad drained attempt %+v", a)
		}
	}
	for i := 0; i < 2; i++ {
		select {
		case <-ended:
		case <-time.After(time.Second):
			t.Fatal("HTTP handler remained")
		}
	}
}

// fetchEndpoint already applies the matcher-specific stale policy. Diagnostics
// must not revalidate its accepted response with an invented zero stale grace.
func TestAsyncDNSPoolDiagnosticAcceptedStaleUsesTransportResult(t *testing.T) {
	r := &asyncDNSClassifierResponse{State: "stale", Route: "ru"}
	if got := asyncDNSPoolDiagnosticOutcome(r, nil, nil); got != "success" {
		t.Fatalf("accepted stale labeled %s", got)
	}
	if got := asyncDNSPoolDiagnosticOutcome(nil, nil, nil); got != "invalid" {
		t.Fatalf("nil labeled %s", got)
	}
	invalid := &asyncDNSFetchError{kind: asyncDNSFailureInvalidResponse, err: errors.New("private invalid payload")}
	if got := asyncDNSPoolDiagnosticOutcome(r, invalid, nil); got != "invalid" {
		t.Fatalf("genuine invalid labeled %s", got)
	}
}
