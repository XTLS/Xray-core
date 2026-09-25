package lua

import (
	"context"
	"errors"
	"sync"

	glua "github.com/yuin/gopher-lua"
)

const maxIdleStates = 16

// LStateFactory must initialize a state fully and observe ctx while doing so.
// The pool owns any non-nil state it returns, even when it also returns an error.
type LStateFactory func(ctx context.Context) (*glua.LState, error)

// Pool lends each state to one caller at a time. It grows on contention and
// keeps up to maxIdleStates idle states until Close. Callers decide whether a
// state is reusable.
type Pool struct {
	ctx    context.Context
	cancel context.CancelFunc

	factory LStateFactory
	idle    []*glua.LState

	mu     sync.Mutex
	active sync.WaitGroup
	closed bool
}

// NewPool initializes one state before returning, so top-level errors surface at startup.
func NewPool(ctx context.Context, factory LStateFactory) (*Pool, error) {
	poolCtx, cancel := context.WithCancel(ctx)

	// Create one state now to catch factory errors at startup.
	state, err := factory(poolCtx)
	if err != nil {
		cancel()
		if state != nil {
			state.Close()
		}
		return nil, err
	}
	if state == nil {
		cancel()
		return nil, errors.New("Lua state factory returned nil")
	}
	if err := poolCtx.Err(); err != nil {
		state.Close()
		cancel()
		return nil, err
	}

	return &Pool{ctx: poolCtx, cancel: cancel, factory: factory, idle: []*glua.LState{state}}, nil
}

// Context is cancelled by Close. Query contexts should derive from it.
func (p *Pool) Context() context.Context {
	return p.ctx
}

// Acquire returns an initialized exclusive state, growing the pool if necessary.
func (p *Pool) Acquire() (*glua.LState, error) {
	p.mu.Lock()
	if p.closed || p.ctx.Err() != nil {
		p.mu.Unlock()
		return nil, p.ctx.Err()
	}

	p.active.Add(1)

	n := len(p.idle)
	if n != 0 {
		state := p.idle[n-1]
		p.idle = p.idle[:n-1]
		p.mu.Unlock()
		return state, nil
	}
	p.mu.Unlock()

	// TODO: Limit the total number of states. When the limit is reached, wait
	// for a Release instead of creating another state; allow the wait to be
	// cancelled by the caller or by Close.
	state, err := p.factory(p.ctx)
	if err == nil && state == nil {
		err = errors.New("Lua state factory returned nil")
	}
	if err != nil {
		if state != nil {
			state.Close()
		}
		p.active.Done()
		return nil, err
	}
	if err := p.ctx.Err(); err != nil {
		state.Close()
		p.active.Done()
		return nil, err
	}

	return state, nil
}

// Release returns a healthy state to the pool and closes a failed or cancelled one.
func (p *Pool) Release(state *glua.LState, reusable bool) {
	if reusable {
		p.mu.Lock()
		if !p.closed && p.ctx.Err() == nil && len(p.idle) < maxIdleStates {
			p.idle = append(p.idle, state)
		} else {
			reusable = false
		}
		p.mu.Unlock()
	}

	if !reusable {
		state.Close()
	}

	p.active.Done()
}

// Close cancels active work, closes idle states, and waits for borrowed states.
func (p *Pool) Close() {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		p.cancel()
		for _, state := range p.idle {
			state.Close()
		}
		p.idle = nil
	}
	p.mu.Unlock()

	p.active.Wait()
}
