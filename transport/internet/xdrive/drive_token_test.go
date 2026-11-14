package xdrive

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type tokenServer struct {
	mu    sync.Mutex
	count int
	mode  int
	delay time.Duration
	srv   *httptest.Server
}

func newTokenServer(mode int, delay time.Duration) *tokenServer {
	ts := &tokenServer{mode: mode, delay: delay}
	ts.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.mu.Lock()
		ts.count++
		mode, delay := ts.mode, ts.delay
		ts.mu.Unlock()
		time.Sleep(delay)
		if mode != http.StatusOK {
			w.WriteHeader(mode)
			w.Write([]byte(`{"error":"temporarily_unavailable"}`))
			return
		}
		w.Write([]byte(`{"access_token":"new-token","expires_in":3600}`))
	}))
	return ts
}

func (ts *tokenServer) requests() int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.count
}

func (ts *tokenServer) storage() *driveStorage {
	return &driveStorage{driveShared: &driveShared{
		tokenClient: ts.srv.Client(),
		tokenURL:    ts.srv.URL + "/token",
	}}
}

func TestTokenSingleFlightDuringOutage(t *testing.T) {
	ts := newTokenServer(http.StatusInternalServerError, 200*time.Millisecond)
	defer ts.srv.Close()
	s := ts.storage()

	var wg sync.WaitGroup
	errs := make(chan error, 9)
	start := make(chan struct{})
	wg.Add(1)
	go func() { defer wg.Done(); <-start; _, err := s.accessToken(context.Background()); errs <- err }()
	close(start)
	// Wait until the single flight is in progress, then pile on waiters.
	deadline := time.Now().Add(2 * time.Second)
	for ts.requests() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	for i := 0; i < 7; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.accessToken(context.Background()); errs <- err }()
	}
	cancelledCtx, cancel := context.WithCancel(context.Background())
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(20 * time.Millisecond)
		cancel()
		_, err := s.accessToken(cancelledCtx)
		errs <- err
	}()
	wg.Wait()
	close(errs)
	var cancelledSeen bool
	for err := range errs {
		if err == nil {
			t.Fatal("an outage caller succeeded")
		}
		if err == context.Canceled {
			cancelledSeen = true
		}
	}
	if !cancelledSeen {
		t.Fatal("the cancelled waiter did not return ctx.Err")
	}
	if n := ts.requests(); n != 1 {
		t.Fatalf("N concurrent callers caused %d token fetches, want 1", n)
	}
}

func TestTokenBackgroundFailureBacksOff(t *testing.T) {
	ts := newTokenServer(http.StatusInternalServerError, 0)
	defer ts.srv.Close()
	s := ts.storage()
	s.token = "cached"
	s.tokenLifetime = 10 * time.Second
	s.tokenExpiry = time.Now().Add(time.Second) // inside the refresh window

	if tok, err := s.accessToken(context.Background()); err != nil || tok != "cached" {
		t.Fatalf("accessToken=%q err=%v", tok, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for ts.requests() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if n := ts.requests(); n != 1 {
		t.Fatalf("background refresh made %d requests, want 1", n)
	}
	// A second call inside the backoff must not hit the endpoint again.
	if _, err := s.accessToken(context.Background()); err != nil {
		t.Fatalf("cached token should still be returned: %v", err)
	}
	if n := ts.requests(); n != 1 {
		t.Fatalf("a failing endpoint was hit %d times, want 1", n)
	}
	s.tokenMu.Lock()
	backoff := s.tokenBackoff
	retryAt := s.tokenRetryAt
	s.tokenMu.Unlock()
	if backoff < tokenRefreshBackoff {
		t.Fatalf("backoff %v below the default %v", backoff, tokenRefreshBackoff)
	}
	if !retryAt.After(time.Now()) {
		t.Fatal("tokenRetryAt not set into the future after a background failure")
	}
}

func TestToken401RefetchOnce(t *testing.T) {
	ts := newTokenServer(http.StatusOK, 0)
	defer ts.srv.Close()
	s := ts.storage()
	s.token = "old"
	s.tokenLifetime = time.Hour
	s.tokenExpiry = time.Now().Add(time.Hour)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.invalidateToken("old")
			if _, err := s.accessToken(context.Background()); err != nil {
				t.Errorf("accessToken: %v", err)
			}
		}()
	}
	wg.Wait()
	if n := ts.requests(); n != 1 {
		t.Fatalf("many 401 handlers caused %d refetches, want 1", n)
	}
	s.tokenMu.Lock()
	tok := s.token
	s.tokenMu.Unlock()
	if tok != "new-token" {
		t.Fatalf("token=%q, want new-token", tok)
	}
	// Invalidating with a stale used token must not clear the fresh one.
	s.invalidateToken("old")
	s.tokenMu.Lock()
	tok = s.token
	s.tokenMu.Unlock()
	if tok != "new-token" {
		t.Fatalf("stale invalidation cleared the fresh token: %q", tok)
	}
}
