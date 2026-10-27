package signal

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/task"
)

type ActivityUpdater interface {
	Update()
}

type ActivityTimer struct {
	mu        sync.RWMutex
	updated   chan struct{}
	checkTask *task.Periodic
	onTimeout func()
	consumed  atomic.Bool
	once      sync.Once
}

func (t *ActivityTimer) Update() {
	select {
	case t.updated <- struct{}{}:
	default:
	}
}

func (t *ActivityTimer) check() error {
	select {
	case <-t.updated:
	default:
		t.finish()
	}
	return nil
}

func (t *ActivityTimer) finish() {
	t.once.Do(func() {
		t.consumed.Store(true)
		t.mu.Lock()
		defer t.mu.Unlock()

		common.CloseIfExists(t.checkTask)
		t.onTimeout()
	})
}

func (t *ActivityTimer) SetTimeout(timeout time.Duration) {
	if t.consumed.Load() {
		return
	}
	if timeout == 0 {
		t.finish()
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	// double check, just in case
	if t.consumed.Load() {
		return
	}
	// Periodic.Start runs Execute once synchronously, here, while t.mu is
	// held. If a check of the task being replaced is still in flight it can
	// take the token posted by Update below; check would then call finish,
	// which locks t.mu again: a self-deadlock that leaks the connection's
	// handler. The synchronous first run only drains the token and never
	// calls check (later runs happen on the timer, after t.mu is released).
	first := true
	newCheckTask := &task.Periodic{
		Interval: timeout,
		Execute: func() error {
			if first {
				first = false
				select {
				case <-t.updated:
				default:
				}
				return nil
			}
			return t.check()
		},
	}
	common.CloseIfExists(t.checkTask)
	t.checkTask = newCheckTask
	t.Update()
	common.Must(newCheckTask.Start())
}

func CancelAfterInactivity(ctx context.Context, cancel context.CancelFunc, timeout time.Duration) *ActivityTimer {
	timer := &ActivityTimer{
		updated:   make(chan struct{}, 1),
		onTimeout: cancel,
	}
	timer.SetTimeout(timeout)
	return timer
}
