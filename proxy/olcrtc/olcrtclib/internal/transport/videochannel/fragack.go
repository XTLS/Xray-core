package videochannel

import "sync"

// fragAckTracker tracks per-fragment acknowledgements for in-flight Send
// calls. Each Send registers a tracker keyed by sequence number with the
// total fragment count; the receive loop calls Mark(seq, fragIdx) when an
// ack arrives. Send polls Snapshot() to see which fragments still need
// retransmission.
//
// The split from common.AckRegistry exists because video transports are
// lossy at the fragment level (each fragment is a separate VP8-encoded
// video frame that may be corrupted past QR/tile decode recovery). Whole-
// message ack semantics forced a full retransmit on any single-fragment
// loss, which under load piled fragments into the outbound channel and
// eventually killed the encoder. Per-fragment ack lets the sender retry
// only what was actually lost.
type fragAckTracker struct {
	mu      sync.Mutex
	pending map[uint32]*fragWaiter
}

type fragWaiter struct {
	mu        sync.Mutex
	crc       uint32
	total     int
	acked     []bool
	remaining int
	notify    chan struct{}
}

func newFragAckTracker() *fragAckTracker {
	return &fragAckTracker{pending: make(map[uint32]*fragWaiter)}
}

// Register installs a waiter for (seq, crc) covering total fragments and
// returns it. The caller must drop it via Unregister.
func (t *fragAckTracker) Register(seq, crc uint32, total int) *fragWaiter {
	w := &fragWaiter{
		crc:       crc,
		total:     total,
		acked:     make([]bool, total),
		remaining: total,
		notify:    make(chan struct{}, 1),
	}
	t.mu.Lock()
	t.pending[seq] = w
	t.mu.Unlock()
	return w
}

// Unregister drops the waiter for seq.
func (t *fragAckTracker) Unregister(seq uint32) {
	t.mu.Lock()
	delete(t.pending, seq)
	t.mu.Unlock()
}

// Mark records that fragIdx of seq is acknowledged. crc must match the
// waiter's crc, otherwise the ack is ignored (it is from an older message
// whose seq was reused). Returns true iff this call actually flipped a
// previously-unacked fragment.
func (t *fragAckTracker) Mark(seq, crc uint32, fragIdx int) bool {
	t.mu.Lock()
	w, ok := t.pending[seq]
	t.mu.Unlock()
	if !ok {
		return false
	}
	w.mu.Lock()
	if w.crc != crc || fragIdx < 0 || fragIdx >= w.total || w.acked[fragIdx] {
		w.mu.Unlock()
		return false
	}
	w.acked[fragIdx] = true
	w.remaining--
	w.mu.Unlock()
	select {
	case w.notify <- struct{}{}:
	default:
	}
	return true
}

// Pending returns the indexes of fragments still unacked.
func (w *fragWaiter) Pending() []int {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]int, 0, w.remaining)
	for i, ok := range w.acked {
		if !ok {
			out = append(out, i)
		}
	}
	return out
}

// Done reports whether every fragment has been acked.
func (w *fragWaiter) Done() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.remaining == 0
}

// Notify returns the channel that ticks on every Mark.
func (w *fragWaiter) Notify() <-chan struct{} {
	return w.notify
}
