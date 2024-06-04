package splithttp

// upload_queue is a specialized priorityqueue + channel to reorder generic
// packets by a sequence number

import (
	"bytes"
	"container/heap"
	"sync"
)

type Packet struct {
	Payload []byte
	Seq     uint64
}

type UploadQueue struct {
	pushEvent  chan struct{}
	heapGuard  sync.Mutex
	heap       uploadHeap
	nextSeq    uint64
	closed     bool
	maxPackets int
}

func NewUploadQueue(maxPackets int) *UploadQueue {
	return &UploadQueue{
		pushEvent:  make(chan struct{}, 2*maxPackets),
		heap:       uploadHeap{},
		nextSeq:    0,
		closed:     false,
		maxPackets: maxPackets,
	}
}

func (h *UploadQueue) Push(p Packet) error {
	if h.closed {
		return newError("splithttp packet queue closed")
	}

	h.heapGuard.Lock()
	heap.Push(&h.heap, p)
	h.heapGuard.Unlock()
	h.pushEvent <- struct{}{}
	return nil
}

func (h *UploadQueue) Read(b []byte) (int, error) {
	for {
		n, err := h.readPoll(b)
		if err != nil || n > 0 {
			return n, err
		}
	}
}

func (h *UploadQueue) Close() error {
	h.closed = true
	return nil
}

func (h *UploadQueue) readPoll(b []byte) (int, error) {
	if h.closed {
		return 0, newError("splithttp packet queue closed")
	}
	<-h.pushEvent
	h.heapGuard.Lock()
	defer h.heapGuard.Unlock()
	packet := heap.Pop(&h.heap).(Packet)
	if packet.Seq == h.nextSeq {
		reader := bytes.NewBuffer(packet.Payload)
		n, err := reader.Read(b)
		if err != nil {
			return n, err
		}
		packet.Payload = reader.Bytes()
		if len(packet.Payload) == 0 {
			h.nextSeq = packet.Seq + 1
		} else {
			heap.Push(&h.heap, packet)
			h.pushEvent <- struct{}{}
		}
		return n, err
	} else {
		heap.Push(&h.heap, packet)
		return 0, nil
	}
}

// heap code directly taken from https://pkg.go.dev/container/heap
type uploadHeap []Packet

func (h uploadHeap) Len() int           { return len(h) }
func (h uploadHeap) Less(i, j int) bool { return h[i].Seq < h[j].Seq }
func (h uploadHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *uploadHeap) Push(x any) {
	// Push and Pop use pointer receivers because they modify the slice's length,
	// not just its contents.
	*h = append(*h, x.(Packet))
}

func (h *uploadHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}
