package signal

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

type ActivityUpdater interface {
	Update()
}

type ActivityTimer struct {
	mu        sync.Mutex
	timer     atomic.Pointer[time.Timer]
	timeout   time.Duration
	onTimeout func()
}

func (t *ActivityTimer) Update() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if timer := t.timer.Load(); timer != nil {
		timer.Reset(t.timeout)
	}
}

func (t *ActivityTimer) finish() {
	if timer := t.timer.Swap(nil); timer != nil {
		timer.Stop()
		t.onTimeout()
	}
}

func (t *ActivityTimer) SetTimeout(timeout time.Duration) {
	if timeout == 0 {
		t.finish()
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if timer := t.timer.Load(); timer != nil {
		t.timeout = timeout
		timer.Reset(timeout)
	}
}

func CancelAfterInactivity(ctx context.Context, cancel context.CancelFunc, timeout time.Duration) *ActivityTimer {
	activityTimer := &ActivityTimer{
		timeout:   timeout,
		onTimeout: cancel,
	}
	if timeout == 0 {
		cancel()
		return activityTimer
	}
	activityTimer.timer.Store(time.AfterFunc(timeout, activityTimer.finish))
	return activityTimer
}
