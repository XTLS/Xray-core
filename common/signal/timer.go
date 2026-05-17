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
	mu sync.Mutex
	// timer will be nil if this timer is already finished
	timer     *time.Timer
	timeout   time.Duration
	onTimeout func()
}

func (t *ActivityTimer) Update() {
	// someone already called Update or closing, just return
	if !t.mu.TryLock() {
		return
	}
	defer t.mu.Unlock()
	if t.timer != nil {
		t.timer.Reset(t.timeout)
	}
}

func (t *ActivityTimer) finish() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.timer != nil {
		t.timer.Stop()
		t.onTimeout()
		t.timer = nil
	}
}

func (t *ActivityTimer) SetTimeout(timeout time.Duration) {
	if timeout == 0 {
		t.finish()
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.timer != nil {
		t.timeout = timeout
		t.timer.Reset(timeout)
	}
}

func CancelAfterInactivity(ctx context.Context, cancel context.CancelFunc, timeout time.Duration) *ActivityTimer {
	activityTimer := &ActivityTimer{
		timeout:   timeout,
		onTimeout: cancel,
	}
	// strange situation
	if timeout == 0 {
		cancel()
		return activityTimer
	}
	activityTimer.timer = time.AfterFunc(timeout, activityTimer.finish)
	return activityTimer
}
