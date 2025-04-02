package task

import (
	"sync"
	"time"
	"log"
)

// Periodic is a task that runs periodically.
type Periodic struct {
	// Interval of the task being run
	Interval time.Duration
	// Execute is the task function
	Execute func() error

	access  sync.Mutex
	timer   *time.Timer
	running bool
}

func (t *Periodic) hasClosed() bool {
	t.access.Lock()
	defer t.access.Unlock()

	return !t.running
}

func (t *Periodic) checkedExecute() {
	if t.hasClosed() {
	    return
	}
	
	go func() {
	    defer func() {
	        if r := recover(); r != nil {
	            log.Printf("[ERROR] Periodic task panic: %v", r)
	        }
	    }()
	
	    if err := t.Execute(); err != nil {
	        log.Printf("[WARN] Periodic task execution failed: %v", err)
	    }
	
	    t.access.Lock()
	    if t.running {
	        t.timer = time.AfterFunc(t.Interval, t.checkedExecute)
	    }
	    t.access.Unlock()
	}()
}

// Start implements common.Runnable.
func (t *Periodic) Start() error {
	t.access.Lock()
	if t.running {
		t.access.Unlock()
		return nil
	}
	t.running = true
	t.access.Unlock()

	if err := t.checkedExecute(); err != nil {
		t.access.Lock()
		t.running = false
		t.access.Unlock()
		return err
	}

	return nil
}

// Close implements common.Closable.
func (t *Periodic) Close() error {
	t.access.Lock()
	defer t.access.Unlock()

	t.running = false
	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}

	return nil
}
