package tun

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

const (
	fragmentKeys     = 256
	fragmentBytes    = 4 << 20
	fragmentPieces   = 256
	fragmentLifetime = 60 * time.Second
)

// IPv6's Fragment Next Header is deliberately not part of the key. The first
// fragment supplies the authoritative header chain, even if it arrives last.
type fragmentKey struct {
	src, dst netip.Addr
	id       uint32
	proto    byte // IPv4 only
}

type ipFragment struct {
	key                 fragmentKey
	header, data        []byte
	offset, previous    int
	next                byte
	more, atomic, valid bool
}

type fragmentPiece struct {
	offset int
	data   []byte
	more   bool
}

type fragmentSet struct {
	expires  time.Time
	header   []byte
	pieces   []fragmentPiece
	final    int // -1 until a last fragment arrives
	retained int
	previous int
	next     byte
	rejected bool
}

// State and its one earliest-expiry timer have one owner. Retained byte slices,
// piece capacities and set allocations share a budget; map overhead is bounded
// separately by fragmentKeys. No buffers are allocated from a supplied offset.
type fragmentReassembler struct {
	mu       sync.Mutex
	closed   atomic.Bool
	sets     map[fragmentKey]*fragmentSet
	retained int
	timer    *time.Timer
	deadline time.Time
}

func (r *fragmentReassembler) process(b []byte) []byte {
	f, fragmented := readIPFragment(b)
	if !fragmented {
		return b
	}
	return r.accept(f, time.Now())
}

// processAt also permits deterministic first-arrival/expiry tests.
func (r *fragmentReassembler) processAt(b []byte, now time.Time) []byte {
	f, fragmented := readIPFragment(b)
	if !fragmented {
		return b
	}
	return r.accept(f, now)
}

func (r *fragmentReassembler) accept(f ipFragment, now time.Time) []byte {
	if r.closed.Load() {
		return nil
	}
	// RFC 6946: atomic fragments do not consult or disturb matching state.
	if f.atomic {
		if !f.valid {
			return nil
		}
		return rebuildFragment(f.header, f.data, f.previous, f.next)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed.Load() {
		return nil
	}
	r.expireLocked(now)
	s := r.sets[f.key]
	if s == nil {
		if len(r.sets) >= fragmentKeys || r.retained+int(unsafe.Sizeof(fragmentSet{})) > fragmentBytes {
			return nil
		}
		if r.sets == nil {
			r.sets = make(map[fragmentKey]*fragmentSet)
		}
		s = &fragmentSet{expires: now.Add(fragmentLifetime), final: -1, retained: int(unsafe.Sizeof(fragmentSet{}))}
		r.sets[f.key] = s
		r.retained += s.retained
	}
	defer r.armLocked()
	if s.rejected {
		return nil
	}
	if !f.valid {
		r.rejectLocked(s)
		return nil
	}
	end := f.offset + len(f.data)
	if s.final >= 0 && (end > s.final || f.more && end >= s.final) {
		r.rejectLocked(s)
		return nil
	}
	for _, p := range s.pieces {
		if f.offset == p.offset && end == p.offset+len(p.data) && f.more == p.more && bytes.Equal(f.data, p.data) {
			return nil // idempotent; neither deadline nor retained capacity changes
		}
		if f.offset < p.offset+len(p.data) && p.offset < end {
			r.rejectLocked(s)
			return nil
		}
		if !f.more && (p.offset+len(p.data) > end || p.more && p.offset+len(p.data) >= end) {
			r.rejectLocked(s)
			return nil
		}
	}
	if !f.more && s.final >= 0 && s.final != end {
		r.rejectLocked(s)
		return nil
	}
	headerSize := 0
	if f.offset == 0 {
		headerSize = len(f.header)
	}
	// Allocate exact capacities; the metadata budget is proportional to the
	// number of received pieces, not the highest claimed fragment offset.
	capacity := cap(s.pieces)
	if len(s.pieces) == capacity {
		capacity = max(1, capacity*2)
	}
	extra := len(f.data) + headerSize + (capacity-cap(s.pieces))*int(unsafe.Sizeof(fragmentPiece{}))
	if len(s.pieces) >= fragmentPieces || r.retained+extra > fragmentBytes {
		r.rejectLocked(s)
		return nil
	}
	if f.offset == 0 {
		s.header = make([]byte, headerSize)
		copy(s.header, f.header)
		s.previous, s.next = f.previous, f.next
	}
	data := make([]byte, len(f.data))
	copy(data, f.data)
	if capacity != cap(s.pieces) {
		pieces := make([]fragmentPiece, len(s.pieces), capacity)
		copy(pieces, s.pieces)
		s.pieces = pieces
	}
	s.pieces = append(s.pieces, fragmentPiece{offset: f.offset, data: data, more: f.more})
	s.retained += extra
	r.retained += extra
	if !f.more {
		s.final = end
	}
	if s.header == nil {
		return nil
	}
	limit := 65535 - len(s.header)
	if f.key.src.Is6() {
		limit += ipv6HeaderSize
	}
	total := 0
	for _, p := range s.pieces {
		if p.offset+len(p.data) > limit {
			r.rejectLocked(s)
			return nil
		}
		total += len(p.data)
	}
	if s.final < 0 || total != s.final {
		return nil
	}
	// Disjoint pieces within [0, final) whose lengths add to final have no gaps.
	packet := make([]byte, len(s.header)+s.final)
	copy(packet, s.header)
	for _, p := range s.pieces {
		copy(packet[len(s.header)+p.offset:], p.data)
	}
	finishFragment(packet, len(s.header), s.previous, s.next)
	r.retained -= s.retained
	delete(r.sets, f.key)
	return packet
}

func (r *fragmentReassembler) rejectLocked(s *fragmentSet) {
	r.retained -= s.retained - int(unsafe.Sizeof(fragmentSet{}))
	s.retained = int(unsafe.Sizeof(fragmentSet{}))
	s.header, s.pieces = nil, nil
	s.rejected = true // keep the key until its original deadline (RFC 5722)
}

func (r *fragmentReassembler) expireLocked(now time.Time) {
	for key, s := range r.sets {
		if !now.Before(s.expires) {
			r.retained -= s.retained
			delete(r.sets, key)
		}
	}
}

func (r *fragmentReassembler) armLocked() {
	var earliest time.Time
	for _, s := range r.sets {
		if earliest.IsZero() || s.expires.Before(earliest) {
			earliest = s.expires
		}
	}
	if earliest.IsZero() {
		if r.timer != nil {
			r.timer.Stop()
			r.timer = nil
		}
		r.deadline = time.Time{}
		return
	}
	if earliest.Equal(r.deadline) {
		return
	}
	r.deadline = earliest
	delay := time.Until(earliest)
	if r.timer == nil {
		r.timer = time.AfterFunc(delay, func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.closed.Load() {
				return
			}
			now := time.Now()
			r.deadline = time.Time{}
			r.expireLocked(now)
			r.armLocked()
		})
	} else {
		r.timer.Reset(delay)
	}
}

func (r *fragmentReassembler) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed.Store(true)
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
	r.sets = nil
	r.retained = 0
	r.deadline = time.Time{}
}

func readIPFragment(b []byte) (f ipFragment, fragmented bool) {
	if len(b) < ipv4HeaderSize {
		return f, false
	}
	switch b[0] >> 4 {
	case 4:
		flags := binary.BigEndian.Uint16(b[6:])
		if flags&0x3fff == 0 {
			return f, false
		}
		f.key = fragmentKey{src: netip.AddrFrom4([4]byte(b[12:16])), dst: netip.AddrFrom4([4]byte(b[16:20])), id: uint32(binary.BigEndian.Uint16(b[4:])), proto: b[9]}
		size, total := int(b[0]&15)*4, int(binary.BigEndian.Uint16(b[2:]))
		f.offset, f.more = int(flags&0x1fff)*8, flags&0x2000 != 0
		if size < ipv4HeaderSize || total <= size || total > len(b) || flags&0xc000 != 0 {
			return f, true
		}
		f.header, f.data = b[:size], b[size:total]
		f.valid = (!f.more || len(f.data)%8 == 0) && f.offset+len(f.data) <= 65535-ipv4HeaderSize
		return f, true
	case 6:
		if len(b) < ipv6HeaderSize {
			return f, false
		}
		total := ipv6HeaderSize + int(binary.BigEndian.Uint16(b[4:]))
		// Scan the available prefix even when the advertised packet is truncated,
		// so a reachable Fragment header can reject an existing matching set.
		available := min(total, len(b))
		next, offset, previous := b[6], ipv6HeaderSize, 6
		for next == 0 || next == 43 || next == 60 {
			size := ipv6ExtensionSize(b[offset:available])
			if size == 0 {
				return f, false
			}
			previous, next, offset = offset, b[offset], offset+size
		}
		if next != 44 || available-offset < 8 {
			return f, false
		}
		frag := b[offset:available]
		bits := binary.BigEndian.Uint16(frag[2:])
		f.key = fragmentKey{src: netip.AddrFrom16([16]byte(b[8:24])), dst: netip.AddrFrom16([16]byte(b[24:40])), id: binary.BigEndian.Uint32(frag[4:])}
		f.offset, f.more = int(bits&0xfff8), bits&1 != 0
		f.atomic = f.offset == 0 && !f.more
		f.header, f.data, f.previous, f.next = b[:offset], frag[8:], previous, frag[0]
		f.valid = total <= len(b) && frag[1] == 0 && bits&6 == 0 && (!f.more || len(f.data)%8 == 0) && f.offset+len(f.data) <= 65535
		if !f.atomic && len(f.data) == 0 {
			f.valid = false
		}
		if f.offset == 0 {
			f.valid = f.valid && len(f.header)-ipv6HeaderSize+len(f.data) <= 65535 && firstFragmentHeaders(f.next, f.data)
		}
		return f, true
	}
	return f, false
}

func ipv6ExtensionSize(b []byte) int {
	if len(b) < 8 {
		return 0
	}
	size := (int(b[1]) + 1) * 8
	if size > len(b) {
		return 0
	}
	return size
}

// RFC 7112: the offset-zero fragment must contain the whole extension chain
// and the upper-layer header for the protocols this stack dispatches.
func firstFragmentHeaders(next byte, b []byte) bool {
	for next == 0 || next == 43 || next == 60 {
		size := ipv6ExtensionSize(b)
		if size == 0 {
			return false
		}
		next, b = b[0], b[size:]
	}
	switch next {
	case 44:
		return false // a second Fragment header cannot be reassembled
	case protoTCP:
		return len(b) >= tcpHeaderSize && int(b[12]>>4)*4 >= tcpHeaderSize && int(b[12]>>4)*4 <= len(b)
	case protoUDP, protoICMPv6:
		return len(b) >= 8
	default:
		return true // unknown upper-layer protocols are not dispatched
	}
}

func rebuildFragment(header, data []byte, previous int, next byte) []byte {
	b := make([]byte, len(header)+len(data))
	copy(b, header)
	copy(b[len(header):], data)
	finishFragment(b, len(header), previous, next)
	return b
}

func finishFragment(b []byte, headerSize, previous int, next byte) {
	if b[0]>>4 == 4 {
		binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
		b[6], b[7], b[10], b[11] = 0, 0, 0, 0
		binary.BigEndian.PutUint16(b[10:], checksum(sum(b[:headerSize], 0)))
	} else {
		b[previous] = next
		binary.BigEndian.PutUint16(b[4:], uint16(len(b)-ipv6HeaderSize))
	}
}
