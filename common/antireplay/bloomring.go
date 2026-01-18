package antireplay

import (
	"hash/fnv"
	"sync"

	"github.com/riobard/go-bloom"
)

type BloomRing struct {
	bloom *bloomRing
	lock  *sync.Mutex
}

func (b BloomRing) Interval() int64 {
	return 9999999
}

func (b BloomRing) Check(sum []byte) bool {
	b.lock.Lock()
	defer b.lock.Unlock()
	if b.bloom.Test(sum) {
		return false
	}
	b.bloom.Add(sum)
	return true
}

func NewBloomRing() BloomRing {
	const (
		DefaultSFCapacity = 1e6
		// FalsePositiveRate
		DefaultSFFPR  = 1e-6
		DefaultSFSlot = 10
	)
	return BloomRing{newBloomRing(DefaultSFSlot, DefaultSFCapacity, DefaultSFFPR), &sync.Mutex{}}
}

// simply use Double FNV here as our Bloom Filter hash
func doubleFNV(b []byte) (uint64, uint64) {
	hx := fnv.New64()
	hx.Write(b)
	x := hx.Sum64()
	hy := fnv.New64a()
	hy.Write(b)
	y := hy.Sum64()
	return x, y
}

type bloomRing struct {
	slotCapacity int
	slotPosition int
	slotCount    int
	entryCounter int
	slots        []bloom.Filter
	mutex        sync.RWMutex
}

func newBloomRing(slot, capacity int, falsePositiveRate float64) *bloomRing {
	// Calculate entries for each slot
	r := &bloomRing{
		slotCapacity: capacity / slot,
		slotCount:    slot,
		slots:        make([]bloom.Filter, slot),
	}
	for i := 0; i < slot; i++ {
		r.slots[i] = bloom.New(r.slotCapacity, falsePositiveRate, doubleFNV)
	}
	return r
}

func (r *bloomRing) Add(b []byte) {
	if r == nil {
		return
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	slot := r.slots[r.slotPosition]
	if r.entryCounter > r.slotCapacity {
		// Move to next slot and reset
		r.slotPosition = (r.slotPosition + 1) % r.slotCount
		slot = r.slots[r.slotPosition]
		slot.Reset()
		r.entryCounter = 0
	}
	r.entryCounter++
	slot.Add(b)
}

func (r *bloomRing) Test(b []byte) bool {
	if r == nil {
		return false
	}
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	for _, s := range r.slots {
		if s.Test(b) {
			return true
		}
	}
	return false
}
