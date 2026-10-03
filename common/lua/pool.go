package lua

import (
	"context"
	"sync"

	glua "github.com/yuin/gopher-lua"
)

const maxIdleStates = 16

// Pool lends each state to one caller at a time. It grows on contention and
// keeps up to maxIdleStates idle states until Close. Acquire/Release callers
// decide reusability; WithState uses its callback's error.
type Pool struct {
	ctx    context.Context
	cancel context.CancelFunc

	factory LStateFactory
	idle    []*glua.LState
	top     int

	mu     sync.Mutex
	active sync.WaitGroup
	closed bool
}

// NewPool tests the factory by creating one state during initialization.
func NewPool(ctx context.Context, factory LStateFactory) (*Pool, error) {
	poolCtx, cancel := context.WithCancel(ctx)

	state, err := factory(poolCtx)
	if err != nil {
		cancel()
		return nil, err
	}

	return &Pool{ctx: poolCtx, cancel: cancel, factory: factory, idle: []*glua.LState{state}, top: state.GetTop()}, nil
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
	if err != nil {
		p.active.Done()
		return nil, err
	}

	return state, nil
}

// WithState runs work on an exclusive state and releases it afterward. A state
// is reusable only when work succeeds; a panic closes it before propagating.
func (p *Pool) WithState(work func(*glua.LState) error) error {
	state, err := p.Acquire()
	if err != nil {
		return err
	}
	reusable := false
	defer func() {
		p.Release(state, reusable)
	}()
	err = work(state)
	reusable = err == nil
	return err
}

// Release returns a healthy state to the pool and closes a failed or cancelled one.
func (p *Pool) Release(state *glua.LState, reusable bool) {
	if reusable {
		state.SetTop(p.top)
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
