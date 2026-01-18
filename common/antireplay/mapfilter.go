package antireplay

import (
	"sync"
	"time"
)

// ReplayFilter checks for replay attacks.
type ReplayFilter struct {
	lock      sync.Mutex
	pool      map[string]struct{}
	interval  int64
	lastClean int64
}

// NewMapFilter create a new filter with specifying the expiration time interval in seconds.
func NewMapFilter(interval int64) *ReplayFilter {
	filter := &ReplayFilter{
		pool:     make(map[string]struct{}),
		interval: interval,
	}
	return filter
}

// Interval in second for expiration time for duplicate records.
func (filter *ReplayFilter) Interval() int64 {
	return filter.interval
}

// Check determines if there are duplicate records.
func (filter *ReplayFilter) Check(sum []byte) bool {
	filter.lock.Lock()
	defer filter.lock.Unlock()

	now := time.Now().Unix()

	elapsed := now - filter.lastClean
	if elapsed >= filter.Interval() {
		filter.pool = make(map[string]struct{})
		filter.lastClean = now
	}

	_, exists := filter.pool[string(sum)]
	filter.pool[string(sum)] = struct{}{}
	return !exists
}
