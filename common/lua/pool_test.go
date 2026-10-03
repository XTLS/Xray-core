package lua

import (
	"context"
	"errors"
	"testing"
	"time"

	glua "github.com/yuin/gopher-lua"
)

func newTestPool(t testing.TB, ctx context.Context, timeout time.Duration, factory LStateFactory) *Pool {
	t.Helper()
	pool, err := NewPool(ctx, timeout, factory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func assertPoolCloseBlocked(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
		t.Fatal("Close returned while work was still active")
	case <-time.After(20 * time.Millisecond):
	}
}

func TestPoolTimeoutValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		timeout time.Duration
		wantErr bool
	}{
		{"zero", 0, true},
		{"negative", -time.Nanosecond, true},
		{"positive", time.Nanosecond, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			pool, err := NewPool(context.Background(), tc.timeout, func(context.Context) (*glua.LState, error) {
				called = true
				return glua.NewState(), nil
			})
			if pool != nil {
				t.Cleanup(pool.Close)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("NewPool error = %v, want error %t", err, tc.wantErr)
			}
			if tc.wantErr && (pool != nil || called) {
				t.Fatal("invalid timeout created a pool or called the factory")
			}
		})
	}
}

func TestPoolFactoryFailure(t *testing.T) {
	failure := errors.New("factory failed")
	_, err := NewPool(context.Background(), time.Second, func(context.Context) (*glua.LState, error) {
		return nil, failure
	})
	if !errors.Is(err, failure) {
		t.Fatalf("NewPool error = %v, want original factory error", err)
	}

	calls := 0
	pool := newTestPool(t, context.Background(), time.Second, func(context.Context) (*glua.LState, error) {
		calls++
		if calls == 1 {
			return glua.NewState(), nil
		}
		return nil, failure
	})
	state, err := pool.Acquire(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Release(state, true)
	err = pool.WithState(nil, 0, func(*glua.LState) error {
		t.Error("work ran after factory failure")
		return nil
	})
	if !errors.Is(err, failure) {
		t.Fatalf("WithState error = %v, want original factory error", err)
	}
}

func TestPoolReusesStatesAndLimitsIdle(t *testing.T) {
	created := 0
	pool := newTestPool(t, context.Background(), time.Second, func(context.Context) (*glua.LState, error) {
		created++
		return glua.NewState(), nil
	})
	var borrowed []*glua.LState
	defer func() {
		for _, state := range borrowed {
			pool.Release(state, false)
		}
	}()
	for range maxIdleStates + 3 {
		state, err := pool.Acquire(nil)
		if err != nil {
			t.Fatal(err)
		}
		borrowed = append(borrowed, state)
		state.SetContext(context.Background())
	}
	states := borrowed
	for _, state := range states {
		pool.Release(state, true)
	}
	borrowed = nil
	open := 0
	for _, state := range states {
		if !state.IsClosed() {
			if state.Context() != nil {
				t.Fatal("Release left a context on a reusable state")
			}
			open++
		}
	}
	if open != maxIdleStates {
		t.Fatalf("retained %d states, want %d", open, maxIdleStates)
	}
	if err := pool.WithState(nil, 0, func(*glua.LState) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if created != len(states) {
		t.Fatalf("created %d states, want %d", created, len(states))
	}
	pool.Close()
	for _, state := range states {
		if !state.IsClosed() {
			t.Fatal("Close left an idle state open")
		}
	}
}

func TestPoolWithStateOptions(t *testing.T) {
	key := struct{}{}
	parent := context.WithValue(context.Background(), key, "pool")
	caller := context.WithValue(context.Background(), key, "caller")
	pool := newTestPool(t, parent, time.Second, func(context.Context) (*glua.LState, error) {
		return glua.NewState(), nil
	})
	for _, tc := range []struct {
		name        string
		ctx         context.Context
		timeout     time.Duration
		wantValue   string
		wantTimeout time.Duration
	}{
		{"defaults", nil, 0, "pool", time.Second},
		{"context", caller, 0, "caller", time.Second},
		{"timeout", nil, 2 * time.Second, "pool", 2 * time.Second},
		{"both", caller, 2 * time.Second, "caller", 2 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			started := time.Now()
			err := pool.WithState(tc.ctx, tc.timeout, func(L *glua.LState) error {
				ctx := L.Context()
				if ctx.Value(key) != tc.wantValue {
					t.Errorf("context value = %v, want %q", ctx.Value(key), tc.wantValue)
				}
				deadline, ok := ctx.Deadline()
				if !ok || deadline.Before(started.Add(tc.wantTimeout)) || deadline.After(time.Now().Add(tc.wantTimeout)) {
					t.Errorf("deadline = %v, want timeout %v", deadline, tc.wantTimeout)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPoolFactoryContext(t *testing.T) {
	caller, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, tc := range []struct {
		name string
		ctx  context.Context
	}{
		{"default", nil},
		{"caller", caller},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var contexts []context.Context
			pool := newTestPool(t, context.Background(), time.Second, func(ctx context.Context) (*glua.LState, error) {
				contexts = append(contexts, ctx)
				return glua.NewState(), nil
			})
			state, err := pool.Acquire(nil)
			if err != nil {
				t.Fatal(err)
			}
			defer pool.Release(state, true)
			if err := pool.WithState(tc.ctx, 2*time.Second, func(*glua.LState) error { return nil }); err != nil {
				t.Fatal(err)
			}
			want := tc.ctx
			if want == nil {
				want = pool.ctx
			}
			if len(contexts) != 2 || contexts[0] != pool.ctx || contexts[1] != want {
				t.Fatal("factory did not receive the initialization and acquisition contexts unchanged")
			}
		})
	}
}

func TestPoolWithStateLifecycle(t *testing.T) {
	failure := errors.New("work failed")
	for _, tc := range []struct {
		name      string
		work      func(*glua.LState, context.CancelFunc) error
		reusable  bool
		wantPanic bool
		wantErr   error
	}{
		{"success", func(*glua.LState, context.CancelFunc) error { return nil }, true, false, nil},
		{"canceled success", func(_ *glua.LState, cancel context.CancelFunc) error {
			cancel()
			return nil
		}, true, false, nil},
		{"error", func(*glua.LState, context.CancelFunc) error { return failure }, false, false, failure},
		{"timeout", func(L *glua.LState, _ context.CancelFunc) error { return L.DoString("while true do end") }, false, false, nil},
		{"panic", func(*glua.LState, context.CancelFunc) error { panic(failure) }, false, true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := newTestPool(t, context.Background(), 10*time.Millisecond, func(context.Context) (*glua.LState, error) {
				state := glua.NewState()
				state.Push(glua.LTrue)
				return state, nil
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var state *glua.LState
			var workCtx context.Context
			var recovered any
			err := func() (err error) {
				defer func() { recovered = recover() }()
				return pool.WithState(ctx, 0, func(L *glua.LState) error {
					state, workCtx = L, L.Context()
					L.Push(glua.LFalse)
					return tc.work(L, cancel)
				})
			}()
			if tc.wantPanic {
				if recovered != failure {
					t.Fatalf("panic = %v, want original panic", recovered)
				}
			} else {
				if recovered != nil || (err == nil) != tc.reusable {
					t.Fatalf("WithState error = %v, panic = %v", err, recovered)
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Fatalf("WithState error = %v, want %v", err, tc.wantErr)
				}
			}
			if workCtx.Err() == nil {
				t.Fatal("WithState did not cancel the execution context")
			}
			if closed := state.IsClosed(); closed == tc.reusable {
				t.Fatalf("state closed = %t, want %t", closed, !tc.reusable)
			}
			if tc.reusable && (state.Context() != nil || state.GetTop() != 1 || state.Get(1) != glua.LTrue) {
				t.Fatal("WithState did not reset the state for reuse")
			}
			if err := pool.WithState(nil, 0, func(L *glua.LState) error {
				if (L == state) != tc.reusable {
					t.Error("unexpected state reuse")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPoolClose(t *testing.T) {
	pool := newTestPool(t, context.Background(), time.Second, func(context.Context) (*glua.LState, error) {
		return glua.NewState(), nil
	})
	finishCtx, finish := context.WithCancel(context.Background())
	t.Cleanup(finish)
	started, done := make(chan *glua.LState, 1), make(chan error, 1)
	var workCtx context.Context
	go func() {
		done <- pool.WithState(nil, 0, func(L *glua.LState) error {
			workCtx = L.Context()
			started <- L
			<-finishCtx.Done()
			return nil
		})
	}()
	var state *glua.LState
	select {
	case state = <-started:
	case <-time.After(time.Second):
		t.Fatal("WithState did not start")
	}
	closed := make(chan struct{})
	go func() {
		pool.Close()
		close(closed)
	}()
	select {
	case <-workCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel work using the pool context")
	}
	if !errors.Is(workCtx.Err(), context.Canceled) {
		t.Fatalf("work context error = %v, want context.Canceled", workCtx.Err())
	}
	assertPoolCloseBlocked(t, closed)
	finish()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("successful work returned an error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("WithState did not finish")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after WithState")
	}
	if !state.IsClosed() {
		t.Fatal("Release returned a state to a closed pool")
	}
	if state, err := pool.Acquire(nil); state != nil || err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("Acquire after Close = %v, %v; want closed pool error", state, err)
	}
	pool.Close()
}

func TestPoolCloseWaitsForFactory(t *testing.T) {
	finishCtx, finish := context.WithCancel(context.Background())
	started, canceled := make(chan struct{}), make(chan struct{})
	first := true
	pool := newTestPool(t, context.Background(), time.Second, func(ctx context.Context) (*glua.LState, error) {
		if first {
			first = false
			return glua.NewState(), nil
		}
		close(started)
		<-ctx.Done()
		close(canceled)
		<-finishCtx.Done()
		return nil, ctx.Err()
	})
	t.Cleanup(finish)
	state, err := pool.Acquire(nil)
	if err != nil {
		t.Fatal(err)
	}
	pool.Release(state, false)
	acquireDone := make(chan error, 1)
	go func() {
		_, err := pool.Acquire(nil)
		acquireDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("state creation did not start")
	}
	closed := make(chan struct{})
	go func() {
		pool.Close()
		close(closed)
	}()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel state creation")
	}
	assertPoolCloseBlocked(t, closed)
	finish()
	select {
	case err := <-acquireDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Acquire error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("state creation did not finish")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after state creation")
	}
}

func TestPoolCloseWaitsForCallerContext(t *testing.T) {
	pool := newTestPool(t, context.Background(), time.Minute, func(context.Context) (*glua.LState, error) {
		return glua.NewState(), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	started, done := make(chan context.Context, 1), make(chan error, 1)
	go func() {
		done <- pool.WithState(ctx, 0, func(L *glua.LState) error {
			started <- L.Context()
			<-L.Context().Done()
			return L.Context().Err()
		})
	}()
	var workCtx context.Context
	select {
	case workCtx = <-started:
	case <-time.After(time.Second):
		t.Fatal("WithState did not start")
	}
	closed := make(chan struct{})
	go func() {
		pool.Close()
		close(closed)
	}()
	select {
	case <-pool.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel the pool context")
	}
	assertPoolCloseBlocked(t, closed)
	if workCtx.Err() != nil || ctx.Err() != nil {
		t.Fatal("Close canceled the caller's execution context")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("WithState error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("WithState did not stop after caller cancellation")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after WithState")
	}
}

func BenchmarkPoolAcquireRelease(b *testing.B) {
	pool := newTestPool(b, context.Background(), time.Second, func(context.Context) (*glua.LState, error) {
		return glua.NewState(), nil
	})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state, err := pool.Acquire(nil)
		if err != nil {
			b.Fatal(err)
		}
		pool.Release(state, true)
	}
}
