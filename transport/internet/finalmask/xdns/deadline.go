package xdns

import (
	"sync"
	"time"
)

type connDeadline struct {
	mu      sync.Mutex
	when    time.Time
	changed chan struct{}
}

func newConnDeadline() *connDeadline {
	return &connDeadline{changed: make(chan struct{})}
}

func (d *connDeadline) set(when time.Time) {
	d.mu.Lock()
	d.when = when
	close(d.changed)
	d.changed = make(chan struct{})
	d.mu.Unlock()
}

func (d *connDeadline) snapshot() (time.Time, <-chan struct{}) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.when, d.changed
}
