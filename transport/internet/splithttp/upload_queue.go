package splithttp

// upload_queue is a specialized priorityqueue + channel to reorder generic
// packets by a sequence number

import (
	"container/heap"
	"io"
)

type Packet struct {
	Payload []byte
	Seq     uint64
}

type UploadQueue struct {
	pushedPackets chan Packet
	heap          uploadHeap
	nextSeq       uint64
	closed        bool
	maxPackets    int
}

func NewUploadQueue(maxPackets int) *UploadQueue {
	return &UploadQueue{
		pushedPackets: make(chan Packet, maxPackets),
		heap:          uploadHeap{},
		nextSeq:       0,
		closed:        false,
		maxPackets:    maxPackets,
	}
}

func (h *UploadQueue) Push(p Packet) error {
	if h.closed {
		return newError("splithttp packet queue closed")
	}

	h.pushedPackets <- p
	return nil
}

func (h *UploadQueue) Close() error {
	h.closed = true
	close(h.pushedPackets)
	return nil
}

func (h *UploadQueue) Read(b []byte) (int, error) {
	if h.closed && len(h.heap) == 0 && len(h.pushedPackets) == 0 {
		return 0, io.EOF
	}

	needMorePackets := false

	if len(h.heap) > 0 {
		packet := heap.Pop(&h.heap).(Packet)
		n := 0

		if packet.Seq == h.nextSeq {
			copy(b, packet.Payload)
			n = min(len(b), len(packet.Payload))

			if n < len(packet.Payload) {
				// partial read
				packet.Payload = packet.Payload[n:]
				heap.Push(&h.heap, packet)
			} else {
				h.nextSeq = packet.Seq + 1
			}

			return n, nil
		}

		// misordered packet
		if packet.Seq > h.nextSeq {
			if len(h.heap) > h.maxPackets {
				// the "reassembly buffer" is too large, and we want to
				// constrain memory usage somehow. let's tear down the
				// connection, and hope the application retries.
				return 0, newError("packet queue is too large")
			}
			heap.Push(&h.heap, packet)
			needMorePackets = true
		}
	} else {
		needMorePackets = true
	}

	if needMorePackets {
		packet, more := <-h.pushedPackets
		if !more {
			return 0, io.EOF
		}
		heap.Push(&h.heap, packet)
	}

	return 0, nil
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
