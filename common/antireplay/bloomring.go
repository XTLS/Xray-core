package antireplay

import (
	"sync"

	ss_bloomring "github.com/v2fly/ss-bloomring"
)

type BloomRing struct {
	*ss_bloomring.BloomRing
	lock *sync.Mutex
}

func (b BloomRing) Interval() int64 {
	return 9999999
}

func (b BloomRing) Check(sum []byte) bool {
	b.lock.Lock()
	defer b.lock.Unlock()
	if b.Test(sum) {
		return false
	}
	b.Add(sum)
	return true
}

func NewBloomRing() BloomRing {
	const (
		DefaultSFCapacity = 1e6
		// FalsePositiveRate
		DefaultSFFPR  = 1e-6
		DefaultSFSlot = 10
	)
	return BloomRing{ss_bloomring.NewBloomRing(DefaultSFSlot, DefaultSFCapacity, DefaultSFFPR), &sync.Mutex{}}
}
