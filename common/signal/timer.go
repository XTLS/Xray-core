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
	updated    chan struct{}
	checkTask  *task.Periodic
	onTimeout  func()
	overridden bool
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
		t.finish(false)
	}
	return nil
}

func (t *ActivityTimer) finish(locked bool) {
	if !locked {
		t.Lock()
		defer t.Unlock()
	}

	if t.onTimeout != nil {
		t.onTimeout()
		t.onTimeout = nil
	}
	if t.checkTask != nil {
		t.checkTask.Close()
		t.checkTask = nil
	}
}

func (t *ActivityTimer) setTimeout(timeout time.Duration) {
	if t.onTimeout == nil {
		return
	}
	if timeout == 0 {
		t.finish(true)
		return
	}

	checkTask := &task.Periodic{
		Interval: timeout,
		Execute:  t.check,
	}

	if t.checkTask != nil {
		t.checkTask.Close()
		t.overridden = true
	}
	t.checkTask = checkTask
	t.Update()
	common.Must(checkTask.Start())
}

func (t *ActivityTimer) SetTimeout(timeout time.Duration) {
	t.Lock()
	t.setTimeout(timeout)
	t.Unlock()
}

func (t *ActivityTimer) SetTimeoutIfNotOverridden(timeout time.Duration) {
	t.Lock()
	if !t.overridden {
		t.setTimeout(timeout)
	}
	t.Unlock()
}

func CancelAfterInactivity(ctx context.Context, cancel context.CancelFunc, timeout time.Duration) *ActivityTimer {
	timer := &ActivityTimer{
		updated:   make(chan struct{}, 1),
		onTimeout: cancel,
	}
	timer.SetTimeout(timeout)
	return timer
}
