package burst

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newConnectivityTestHealthPing(ctx context.Context, connectivity string, timeout time.Duration) *HealthPing {
	return NewHealthPing(ctx, nil, &HealthPingConfig{
		Destination:  "://invalid",
		Connectivity: connectivity,
		Timeout:      int64(timeout),
		HttpMethod:   http.MethodHead,
	})
}

func TestHealthPingCoalescesConnectivityChecks(t *testing.T) {
	const failures = 8

	var requests atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		if requests.Add(1) == 1 {
			close(started)
		}
		<-release
	}))
	defer server.Close()

	h := newConnectivityTestHealthPing(context.Background(), server.URL, time.Second)
	tags := make([]string, failures)
	for i := range tags {
		tags[i] = fmt.Sprintf("failing-outbound-%d", i)
	}
	done := make(chan struct{})
	go func() {
		h.doCheck(context.Background(), tags, 0, 1)
		close(done)
	}()

	<-started
	time.Sleep(100 * time.Millisecond)
	if got := requests.Load(); got != 1 {
		t.Fatalf("connectivity requests while failures overlap = %d, want 1", got)
	}
	close(release)
	<-done
	if got := requests.Load(); got != 1 {
		t.Fatalf("connectivity requests = %d, want 1", got)
	}
}

func TestHealthPingDoesNotCacheConnectivityChecks(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()

	h := newConnectivityTestHealthPing(context.Background(), server.URL, time.Second)
	h.doCheck(context.Background(), []string{"first"}, 0, 1)
	h.doCheck(context.Background(), []string{"second"}, 0, 1)

	if got := requests.Load(); got != 2 {
		t.Fatalf("connectivity requests across independent checks = %d, want 2", got)
	}
}

func TestHealthPingSharesConnectivityResult(t *testing.T) {
	for _, test := range []struct {
		name string
		want bool
	}{
		{name: "success", want: true},
		{name: "failure", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			const waiters = 8
			var requests atomic.Int32
			started := make(chan struct{})
			release := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if requests.Add(1) == 1 {
					close(started)
				}
				<-release
				if !test.want {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Errorf("hijack connection: %v", err)
						return
					}
					conn.Close()
				}
			}))
			defer server.Close()

			h := newConnectivityTestHealthPing(context.Background(), server.URL, time.Second)
			start := make(chan struct{})
			results := make(chan bool, waiters)
			var ready sync.WaitGroup
			ready.Add(waiters)
			for range waiters {
				go func() {
					ready.Done()
					<-start
					results <- h.checkConnectivity(context.Background())
				}()
			}
			ready.Wait()
			close(start)
			<-started
			time.Sleep(100 * time.Millisecond)
			close(release)

			for range waiters {
				if got := <-results; got != test.want {
					t.Errorf("connectivity result = %v, want %v", got, test.want)
				}
			}
			if got := requests.Load(); got != 1 {
				t.Fatalf("connectivity requests = %d, want 1", got)
			}
		})
	}
}

func TestHealthPingConnectivityCancellationDoesNotCancelSharedProbe(t *testing.T) {
	var requests atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
		close(started)
		<-release
	}))
	defer server.Close()

	h := newConnectivityTestHealthPing(context.Background(), server.URL, time.Second)
	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	first := make(chan bool, 1)
	go func() {
		first <- h.checkConnectivity(waiterCtx)
	}()
	<-started
	second := make(chan bool, 1)
	go func() {
		second <- h.checkConnectivity(context.Background())
	}()
	cancelWaiter()
	if got := <-first; got {
		t.Fatal("canceled waiter reported connectivity success")
	}
	close(release)
	if got := <-second; !got {
		t.Fatal("uncanceled waiter did not receive shared success")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("connectivity requests = %d, want 1", got)
	}
}

func TestHealthPingConnectivityProbeHonorsTimeout(t *testing.T) {
	const timeout = 50 * time.Millisecond
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(started)
		<-request.Context().Done()
	}))
	defer server.Close()

	h := newConnectivityTestHealthPing(context.Background(), server.URL, timeout)
	done := make(chan bool, 1)
	start := time.Now()
	go func() {
		done <- h.checkConnectivity(context.Background())
	}()
	<-started
	if got := <-done; got {
		t.Fatal("timed out connectivity probe reported success")
	}
	if elapsed := time.Since(start); elapsed > 10*timeout {
		t.Fatalf("connectivity probe took %s, want at most %s", elapsed, 10*timeout)
	}
}

func TestHealthPingConnectivityChecksArePerInstance(t *testing.T) {
	var requests atomic.Int32
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
		started <- struct{}{}
		<-release
	}))
	defer server.Close()

	first := newConnectivityTestHealthPing(context.Background(), server.URL, time.Second)
	second := newConnectivityTestHealthPing(context.Background(), server.URL, time.Second)
	results := make(chan bool, 2)
	go func() { results <- first.checkConnectivity(context.Background()) }()
	go func() { results <- second.checkConnectivity(context.Background()) }()
	<-started
	<-started
	close(release)
	<-results
	<-results
	if got := requests.Load(); got != 2 {
		t.Fatalf("connectivity requests from separate HealthPing instances = %d, want 2", got)
	}
}
