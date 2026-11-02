package proxy

import "testing"

type fakeCounter struct {
	value int64
}

func (c *fakeCounter) Value() int64 { return c.value }

func (c *fakeCounter) Set(v int64) int64 {
	old := c.value
	c.value = v
	return old
}

func (c *fakeCounter) Add(v int64) int64 {
	old := c.value
	c.value += v
	return old
}

func TestSpliceProgressFinish(t *testing.T) {
	read, write := &fakeCounter{}, &fakeCounter{}
	p := &spliceProgress{readCounter: read, writeCounter: write}

	p.finish(100)
	if read.value != 100 || write.value != 100 {
		t.Fatalf("finish(100) = (%d, %d), want (100, 100)", read.value, write.value)
	}

	// finish only reports the unreported remainder; a smaller total must not
	// subtract from counters that are already ahead.
	p.finish(80)
	if read.value != 100 || write.value != 100 {
		t.Fatalf("finish(80) = (%d, %d), want (100, 100)", read.value, write.value)
	}
}

func TestSpliceProgressAddIgnoresNonPositive(t *testing.T) {
	read := &fakeCounter{}
	p := &spliceProgress{readCounter: read}
	p.add(0)
	p.add(-1)
	if read.value != 0 {
		t.Fatalf("counter = %d, want 0", read.value)
	}
}
