// Package common provides building blocks shared by the video-track based
// transports (videochannel, seichannel) - fragment/reassembly, ack waiters,
// and per-peer random IDs. vp8channel does its own KCP-based framing and
// only consumes RandomID.
package common

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"sync"
	"time"
)

// RandomID returns 8 random hex characters for use as a per-peer suffix on
// track and stream IDs. Required for Jitsi: msid collisions between
// participants cause Jicofo to reject session-accept.
func RandomID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%08x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// FragmentPayload splits data into chunks of at most maxSize bytes. An empty
// payload produces a single empty fragment so the caller can still ack a
// zero-byte message round-trip.
func FragmentPayload(data []byte, maxSize int) [][]byte {
	if len(data) == 0 {
		return [][]byte{{}}
	}
	out := make([][]byte, 0, (len(data)+maxSize-1)/maxSize)
	for start := 0; start < len(data); start += maxSize {
		end := start + maxSize
		if end > len(data) {
			end = len(data)
		}
		chunk := make([]byte, end-start)
		copy(chunk, data[start:end])
		out = append(out, chunk)
	}
	return out
}

// Fragment describes one piece of a fragmented message on the wire.
type Fragment struct {
	Seq       uint32
	CRC       uint32
	TotalLen  uint32
	FragIdx   uint16
	FragTotal uint16
	Payload   []byte
}

// InboundMessage tracks reassembly state for one inbound message.
type InboundMessage struct {
	TotalLen uint32
	CRC      uint32
	frags    [][]byte
	remain   int
	// added is the monotonic insertion counter used to evict the oldest
	// incomplete message when the pending set exceeds its cap.
	added uint64
}

// Reassembler holds inbound message state and a sliding window of recently
// delivered (seq, crc) pairs so duplicate fragments resolve to a fresh ack
// rather than a re-delivery.
type Reassembler struct {
	mu        sync.Mutex
	inbound   map[uint32]*InboundMessage
	delivered map[uint32]uint32
	maxRecent int
	// maxPending bounds the number of incomplete messages held at once.
	// Lost fragments (routine on video transports behind an SFU) would
	// otherwise leak these entries forever; once the cap is hit we evict
	// the oldest incomplete message to make room.
	maxPending int
	addCounter uint64
}

// NewReassembler creates a reassembler with the given recent-delivery cap.
// When the delivered map exceeds maxRecent entries it is reset; a value of
// 256 is a reasonable default for the video transports.
func NewReassembler(maxRecent int) *Reassembler {
	if maxRecent <= 0 {
		maxRecent = 256
	}
	return &Reassembler{
		inbound:    make(map[uint32]*InboundMessage),
		delivered:  make(map[uint32]uint32),
		maxRecent:  maxRecent,
		maxPending: maxRecent,
	}
}

// Result classifies what Push computed for a fragment.
type Result int

const (
	// ResultIgnore means the fragment was malformed or out of range.
	ResultIgnore Result = iota
	// ResultPartial means the fragment was stored but the message is not
	// fully reassembled yet.
	ResultPartial
	// ResultDuplicate means the message identified by (Seq, CRC) was
	// already delivered. Caller should re-ack without invoking OnData.
	ResultDuplicate
	// ResultDelivered means the message is complete; Data carries the
	// reassembled payload.
	ResultDelivered
)

// Push integrates fragment into reassembly state and returns one of the
// Result values. When ResultDelivered, the second return holds the
// reassembled payload bytes; otherwise it is nil.
func (r *Reassembler) Push(fragment Fragment) (Result, []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if crc, ok := r.delivered[fragment.Seq]; ok && crc == fragment.CRC {
		return ResultDuplicate, nil
	}

	msg := r.upsert(fragment)
	if int(fragment.FragIdx) >= len(msg.frags) {
		return ResultIgnore, nil
	}
	r.storeChunk(msg, fragment)
	if msg.remain > 0 {
		return ResultPartial, nil
	}
	return r.deliver(fragment.Seq, msg)
}

// upsert returns the inbound message tracking entry for fragment.Seq,
// creating a fresh entry if no compatible one is present.
func (r *Reassembler) upsert(fragment Fragment) *InboundMessage {
	msg, ok := r.inbound[fragment.Seq]
	if ok && msg.CRC == fragment.CRC && msg.TotalLen == fragment.TotalLen &&
		len(msg.frags) == int(fragment.FragTotal) {
		return msg
	}
	r.addCounter++
	msg = &InboundMessage{
		TotalLen: fragment.TotalLen,
		CRC:      fragment.CRC,
		frags:    make([][]byte, fragment.FragTotal),
		remain:   int(fragment.FragTotal),
		added:    r.addCounter,
	}
	r.inbound[fragment.Seq] = msg
	r.evictOldestIfFull(fragment.Seq)
	return msg
}

// evictOldestIfFull drops the oldest incomplete message when the pending set
// exceeds its cap, preventing unbounded memory growth from messages whose
// fragments are never fully received. keep is never evicted - it is the entry
// the current Push is about to populate.
func (r *Reassembler) evictOldestIfFull(keep uint32) {
	if r.maxPending <= 0 || len(r.inbound) <= r.maxPending {
		return
	}
	var (
		oldestSeq   uint32
		oldestAdded uint64
		found       bool
	)
	for seq, m := range r.inbound {
		if seq == keep {
			continue
		}
		if !found || m.added < oldestAdded {
			oldestSeq, oldestAdded, found = seq, m.added, true
		}
	}
	if found {
		delete(r.inbound, oldestSeq)
	}
}

func (r *Reassembler) storeChunk(msg *InboundMessage, fragment Fragment) {
	if msg.frags[fragment.FragIdx] != nil {
		return
	}
	chunk := make([]byte, len(fragment.Payload))
	copy(chunk, fragment.Payload)
	msg.frags[fragment.FragIdx] = chunk
	msg.remain--
}

func (r *Reassembler) deliver(seq uint32, msg *InboundMessage) (Result, []byte) {
	delete(r.inbound, seq)
	data := assemble(msg)
	if crc32.ChecksumIEEE(data) != msg.CRC {
		return ResultIgnore, nil
	}
	if len(r.delivered) > r.maxRecent {
		r.delivered = make(map[uint32]uint32)
	}
	r.delivered[seq] = msg.CRC
	return ResultDelivered, data
}

func assemble(msg *InboundMessage) []byte {
	out := make([]byte, 0, msg.TotalLen)
	for _, frag := range msg.frags {
		out = append(out, frag...)
	}
	if uint32(len(out)) > msg.TotalLen { //nolint:gosec // G115: bounded by allocation size
		out = out[:msg.TotalLen]
	}
	return out
}

// AckRegistry tracks in-flight Send calls waiting for their peer ack. Each
// Send registers a waiter keyed by sequence number and reads from it; the
// receive loop calls Resolve when an ack arrives.
type AckRegistry struct {
	mu      sync.Mutex
	waiters map[uint32]chan uint32
}

// NewAckRegistry creates an empty ack registry.
func NewAckRegistry() *AckRegistry {
	return &AckRegistry{waiters: make(map[uint32]chan uint32)}
}

// Register installs a waiter for seq and returns its channel. The caller
// must drop the waiter via Unregister when it is done.
func (a *AckRegistry) Register(seq uint32) chan uint32 {
	ch := make(chan uint32, 1)
	a.mu.Lock()
	a.waiters[seq] = ch
	a.mu.Unlock()
	return ch
}

// Unregister drops the waiter for seq.
func (a *AckRegistry) Unregister(seq uint32) {
	a.mu.Lock()
	delete(a.waiters, seq)
	a.mu.Unlock()
}

// Resolve delivers crc to the waiter for seq, if present. A missing waiter
// is silently ignored - the sender has already moved on.
func (a *AckRegistry) Resolve(seq, crc uint32) {
	a.mu.Lock()
	waiter := a.waiters[seq]
	a.mu.Unlock()
	if waiter == nil {
		return
	}
	select {
	case waiter <- crc:
	default:
	}
}
