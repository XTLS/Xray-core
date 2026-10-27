package signal

import (
	"context"
	"sync"
	"time"
)

type ActivityUpdater interface {
	Update()
}

type ActivityTimer struct {
	mu        sync.RWMutex
	updated   chan struct{}
	checker   *time.Timer
	timeout   time.Duration
	onTimeout func()
	consumed  bool
}

func (t *ActivityTimer) Update() {
	select {
	case t.updated <- struct{}{}:
	default:
	}
}

func (t *ActivityTimer) check() bool {
	select {
	case <-t.updated:
		return true
	default:
		t.finish()
		return false
	}
}

func (t *ActivityTimer) finish() {
	t.mu.Lock()
	if t.consumed {
		t.mu.Unlock()
		return
	}
	t.checker.Stop()
	t.consumed = true
	t.mu.Unlock()
	t.onTimeout()
}

func (t *ActivityTimer) SetTimeout(timeout time.Duration) {
	if timeout == 0 {
		t.finish()
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.consumed {
		return
	}
	t.timeout = timeout
	t.checker.Reset(timeout)
}

func CancelAfterInactivity(ctx context.Context, cancel context.CancelFunc, timeout time.Duration) *ActivityTimer {
	timer := &ActivityTimer{
		updated:   make(chan struct{}, 1),
		onTimeout: cancel,
		timeout:   timeout,
	}
	timer.checker = time.AfterFunc(timeout, func() {
		if timer.check() {
			timer.mu.Lock()
			defer timer.mu.Unlock()
			if timer.consumed {
				return
			}
			timer.checker.Reset(timer.timeout)
		}
	})
	if timeout == 0 {
		timer.SetTimeout(0)
	}
	return timer
}
