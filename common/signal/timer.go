package signal

import (
	"context"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/task"
)

type ActivityUpdater interface {
	Update()
}

type ActivityTimer struct {
	sync.RWMutex
	updated   chan struct{}
	checkTask *task.Periodic
	onTimeout func()
	consumed  bool
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
		t.Lock()
		defer t.Unlock()

		t.onTimeout()
		t.checkTask.Close()
		t.consumed = true
	})
}

func (t *ActivityTimer) SetTimeout(timeout time.Duration) {
	if t.consumed {
		return
	}
	if timeout == 0 {
		t.finish()
		return
	}

	newCheckTask := &task.Periodic{
		Interval: timeout,
		Execute:  t.check,
	}

	t.Lock()
	defer t.Unlock()

	// only in initial
	if t.checkTask != nil {
		t.checkTask.Close()
	}
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
