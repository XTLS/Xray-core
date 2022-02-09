package antireplay

import (
	"sync"
	"time"

	cuckoo "github.com/seiflotfy/cuckoofilter"
)

const replayFilterCapacity = 100000

// ReplayFilter checks for replay attacks.
type ReplayFilter struct {
	lock     sync.Mutex
	poolA    *cuckoo.Filter
	poolB    *cuckoo.Filter
	poolSwap bool
	lastSwap int64
	interval int64
}

// NewReplayFilter create a new filter with specifying the expiration time interval in seconds.
func NewReplayFilter(interval int64) *ReplayFilter {
	filter := &ReplayFilter{}
	filter.interval = interval
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
	if filter.lastSwap == 0 {
		filter.lastSwap = now
		filter.poolA = cuckoo.NewFilter(replayFilterCapacity)
		filter.poolB = cuckoo.NewFilter(replayFilterCapacity)
	}

	elapsed := now - filter.lastSwap
	if elapsed >= filter.Interval() {
		if filter.poolSwap {
			filter.poolA.Reset()
		} else {
			filter.poolB.Reset()
		}
		filter.poolSwap = !filter.poolSwap
		filter.lastSwap = now
	}

	return filter.poolA.InsertUnique(sum) && filter.poolB.InsertUnique(sum)
}
