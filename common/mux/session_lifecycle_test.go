package mux

import (
	"context"
	"testing"
	"time"
)

func waitForContextCancellation(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for session-owned context cancellation")
	}
}

func TestSessionCloseCancelsOwnedContext(t *testing.T) {
	manager := NewSessionManager()
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{
		parent: manager,
		cancel: cancel,
		ID:     1,
	}
	if !manager.Add(s) {
		t.Fatal("failed to add session")
	}

	if err := s.Close(false); err != nil {
		t.Fatal(err)
	}
	waitForContextCancellation(t, ctx)
	if err := s.Close(false); err != nil {
		t.Fatal(err)
	}
}

func TestSessionManagerCloseCancelsOwnedContexts(t *testing.T) {
	manager := NewSessionManager()
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{
		parent: manager,
		cancel: cancel,
		ID:     1,
	}
	if !manager.Add(s) {
		t.Fatal("failed to add session")
	}

	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	waitForContextCancellation(t, ctx)
}
