package lua

import (
	"context"
	"errors"
	"testing"
	"time"

	glua "github.com/yuin/gopher-lua"
)

func TestPoolFactoryFailureClosesReturnedState(t *testing.T) {
	failure := errors.New("factory failed")
	state := glua.NewState()
	_, err := NewPool(context.Background(), func(context.Context) (*glua.LState, error) {
		return state, failure
	})
	if !errors.Is(err, failure) || !state.IsClosed() {
		t.Fatalf("NewPool error = %v, state closed = %t", err, state.IsClosed())
	}

	var failedState *glua.LState
	calls := 0
	pool, err := NewPool(context.Background(), func(context.Context) (*glua.LState, error) {
		calls++
		if calls == 1 {
			return glua.NewState(), nil
		}
		failedState = glua.NewState()
		return failedState, failure
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	borrowed, err := pool.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Release(borrowed, true)
	_, err = pool.Acquire()
	if !errors.Is(err, failure) || !failedState.IsClosed() {
		t.Fatalf("Acquire error = %v, state closed = %t", err, failedState.IsClosed())
	}
}

func TestPoolReusesStatesAndLimitsIdle(t *testing.T) {
	created := 0
	pool, err := NewPool(context.Background(), func(context.Context) (*glua.LState, error) {
		created++
		return glua.NewState(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	states := make([]*glua.LState, maxIdleStates+3)
	for i := range states {
		states[i], err = pool.Acquire()
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, state := range states {
		pool.Release(state, true)
	}
	for i, state := range states {
		if got, want := state.IsClosed(), i >= maxIdleStates; got != want {
			t.Fatalf("state %d closed = %t, want %t", i, got, want)
		}
	}
	borrowed, err := pool.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if created != len(states) {
		t.Fatalf("Acquire created %d states, want %d", created, len(states))
	}
	pool.Release(borrowed, true)
}

func TestPoolCloseCancelsAndWaitsForBorrowedState(t *testing.T) {
	pool, err := NewPool(context.Background(), func(context.Context) (*glua.LState, error) {
		return glua.NewState(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	state, err := pool.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		pool.Close()
		close(done)
	}()
	select {
	case <-pool.Context().Done():
	case <-time.After(time.Second):
		pool.Release(state, false)
		t.Fatal("Close did not cancel the pool context")
	}
	select {
	case <-done:
		pool.Release(state, false)
		t.Fatal("Close returned while a state was borrowed")
	default:
	}
	pool.Release(state, true)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after Release")
	}
	if !state.IsClosed() {
		t.Fatal("borrowed state was not closed")
	}
	if _, err := pool.Acquire(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Acquire after Close = %v, want context.Canceled", err)
	}
	pool.Close()
}

func TestPoolCloseCancelsStateCreation(t *testing.T) {
	started := make(chan struct{})
	first := true
	pool, err := NewPool(context.Background(), func(ctx context.Context) (*glua.LState, error) {
		if first {
			first = false
			return glua.NewState(), nil
		}
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	borrowed, err := pool.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	acquireDone := make(chan error, 1)
	go func() {
		_, err := pool.Acquire()
		acquireDone <- err
	}()
	<-started
	closeDone := make(chan struct{})
	go func() {
		pool.Close()
		close(closeDone)
	}()
	select {
	case err := <-acquireDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Acquire during Close = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("state creation did not stop after Close")
	}
	select {
	case <-closeDone:
		pool.Release(borrowed, false)
		t.Fatal("Close returned while the initial state was borrowed")
	default:
	}
	pool.Release(borrowed, true)
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after Release")
	}
}

func BenchmarkPoolAcquireRelease(b *testing.B) {
	pool, err := NewPool(context.Background(), func(context.Context) (*glua.LState, error) {
		return glua.NewState(), nil
	})
	if err != nil {
		b.Fatal(err)
	}
	defer pool.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state, err := pool.Acquire()
		if err != nil {
			b.Fatal(err)
		}
		pool.Release(state, true)
	}
	b.StopTimer()
}
