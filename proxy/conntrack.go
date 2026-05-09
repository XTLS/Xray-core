package proxy

import (
	"context"
	"io"
	"strings"
	"sync"
	"sync/atomic"
)

type trackedConn struct {
	cancel context.CancelFunc
	closer io.Closer // the actual network connection
}

// ConnTracker tracks active connections per user email and supports
// killing all connections for a given user on removal.
// It both cancels the context AND closes the underlying connection
// to ensure immediate termination even for long-lived streams.
type ConnTracker struct {
	mu    sync.Mutex
	conns map[string]map[uint64]*trackedConn
	seq   atomic.Uint64
}

func NewConnTracker() *ConnTracker {
	return &ConnTracker{
		conns: make(map[string]map[uint64]*trackedConn),
	}
}

// Track registers a connection under the given email.
// conn is the underlying network connection that will be forcibly closed
// when KillAll is called. It may be nil if only context cancellation is needed.
// Returns a wrapped context and a cleanup function that MUST be deferred.
func (t *ConnTracker) Track(ctx context.Context, email string, conn io.Closer) (context.Context, context.CancelFunc, func()) {
	ctx, cancel := context.WithCancel(ctx)
	key := strings.ToLower(email)
	id := t.seq.Add(1)

	t.mu.Lock()
	if t.conns[key] == nil {
		t.conns[key] = make(map[uint64]*trackedConn)
	}
	t.conns[key][id] = &trackedConn{cancel: cancel, closer: conn}
	t.mu.Unlock()

	cleanup := func() {
		cancel()
		t.mu.Lock()
		delete(t.conns[key], id)
		if len(t.conns[key]) == 0 {
			delete(t.conns, key)
		}
		t.mu.Unlock()
	}
	return ctx, cancel, cleanup
}

// KillAll cancels all active connections for the given email
// and forcibly closes the underlying network connections.
func (t *ConnTracker) KillAll(email string) {
	key := strings.ToLower(email)
	t.mu.Lock()
	entries := t.conns[key]
	delete(t.conns, key)
	t.mu.Unlock()

	for _, tc := range entries {
		tc.cancel()
		if tc.closer != nil {
			tc.closer.Close()
		}
	}
}

// Count returns the number of active connections for the given email.
func (t *ConnTracker) Count(email string) int {
	key := strings.ToLower(email)
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.conns[key])
}
