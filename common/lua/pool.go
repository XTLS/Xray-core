package lua

import (
	"context"
	"errors"
	"sync"
	"time"

	glua "github.com/yuin/gopher-lua"
)

const maxIdleStates = 16

// Pool lends each state to one caller at a time. It grows on contention and
// keeps up to maxIdleStates idle states until Close. Acquire/Release callers
// decide reusability; WithState uses its callback's error.
type Pool struct {
	ctx     context.Context
	cancel  context.CancelFunc
	timeout time.Duration

	factory LStateFactory
	idle    []*glua.LState
	top     int

	mu     sync.Mutex
	active sync.WaitGroup
	closed bool
}

// NewPool tests the factory by creating one state during initialization.
func NewPool(ctx context.Context, timeout time.Duration, factory LStateFactory) (*Pool, error) {
	if timeout <= 0 {
		return nil, errors.New("Lua pool timeout must be positive")
	}

	poolCtx, cancel := context.WithCancel(ctx)

	state, err := factory(poolCtx)
	if err != nil {
		cancel()
		return nil, err
	}

	return &Pool{ctx: poolCtx, cancel: cancel, timeout: timeout, factory: factory, idle: []*glua.LState{state}, top: state.GetTop()}, nil
}

// Acquire returns an initialized exclusive state, growing the pool if necessary.
// ctx is passed to the factory for state creation; nil uses the pool context.
func (p *Pool) Acquire(ctx context.Context) (*glua.LState, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errors.New("Lua pool is closed")
	}
	if err := p.ctx.Err(); err != nil {
		p.mu.Unlock()
		return nil, err
	}
	if ctx == nil {
		ctx = p.ctx
	} else if err := ctx.Err(); err != nil {
		p.mu.Unlock()
		return nil, err
	}

	p.active.Add(1)

	n := len(p.idle)
	if n != 0 {
		state := p.idle[n-1]
		p.idle[n-1] = nil
		p.idle = p.idle[:n-1]
		p.mu.Unlock()
		return state, nil
	}
	p.mu.Unlock()

	// TODO: Limit the total number of states. When the limit is reached, wait
	// for a Release instead of creating another state; allow the wait to be
	// cancelled by the caller or by Close.
	state, err := p.factory(ctx)
	if err != nil {
		p.active.Done()
		return nil, err
	}

	return state, nil
}

// WithState runs work on an exclusive state and releases it afterward.
// Nil ctx and zero timeout use pool defaults. The timeout starts after acquisition.
func (p *Pool) WithState(ctx context.Context, timeout time.Duration, work func(*glua.LState) error) error {
	state, err := p.Acquire(ctx)
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = p.ctx
	}
	if timeout == 0 {
		timeout = p.timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	state.SetContext(ctx)
	reusable := false
	defer func() {
		cancel()
		p.Release(state, reusable)
	}()
	err = work(state)
	reusable = err == nil
	return err
}

// Release resets a state for reuse or closes it.
func (p *Pool) Release(state *glua.LState, reusable bool) {
	if reusable {
		state.RemoveContext()
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

// Close cancels the pool context, closes idle states, and waits for borrowed states.
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
