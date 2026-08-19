package rawpacket

import (
	"math/rand"
	"sync"
	"time"
)

// TCPSimState simulates a plausible TCP conversation between the client
// and the relay so middleboxes see a normal connection: SYN with TCP
// options, then ACK segments with monotonically increasing sequence
// numbers and correct acknowledgements.
//
// The client and the relay each keep one state per tunnel session.
// The client is the "active opener" (sends SYN, then ACKs), the relay is
// the "passive opener" (replies SYN|ACK, then ACKs). Which role a state
// plays is decided by the first outbound segment: client role sends a
// bare SYN, server role sends SYN|ACK.
type TCPSimState struct {
	mu       sync.Mutex
	isn      uint32 // our initial sequence number
	seq      uint32 // next sequence number to send
	synSent  bool   // our SYN (or SYN|ACK) has been sent
	peerISN  uint32 // peer's initial sequence number
	peerSeq  uint32 // peer's next expected sequence number (peer's last seq + 1)
	peerSeen bool
}

func newTCPSimState() *TCPSimState {
	isn := uint32(rand.Int63n(1 << 31))
	return &TCPSimState{isn: isn, seq: isn}
}

// nextSeq returns the sequence number to use for an outbound segment of
// the given payload length and advances the counter. Zero-length segments
// (keepalives) do not consume sequence numbers.
func (s *TCPSimState) nextSeq(payloadLen int) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := s.seq
	if payloadLen > 0 {
		s.seq += uint32(payloadLen)
	}
	return seq
}

// flags returns the flags for the next outbound segment in client role.
func (s *TCPSimState) clientFlags() uint8 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.synSent {
		s.synSent = true
		return TCPFlagSyn
	}
	return TCPFlagAck
}

// flags returns the flags for the next outbound segment in server role.
func (s *TCPSimState) serverFlags() uint8 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.synSent {
		s.synSent = true
		return TCPFlagSyn | TCPFlagAck
	}
	return TCPFlagAck
}

// ack returns the acknowledgement number for the next outbound segment:
// the peer's last seen sequence number plus one, or zero before the peer
// is seen.
func (s *TCPSimState) ack() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.peerSeen {
		return 0
	}
	return s.peerSeq
}

// observePeer records the peer's latest segment (its wire sequence number
// and payload length) so outbound acknowledgements stay plausible. The
// first segment is the peer's SYN and consumes one byte; later segments
// advance by their payload length only.
func (s *TCPSimState) observePeer(seq uint32, payloadLen int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.peerSeen {
		s.peerSeen = true
		s.peerISN = seq
		s.peerSeq = seq + 1 + uint32(payloadLen)
		return
	}
	s.peerSeq = seq + uint32(payloadLen)
}

// observeClientSeq records the client's latest wire sequence number so
// server-role acknowledgements are correct. Used on the relay, where the
// client's cumulative sequence is already encoded in the wire seq. The
// first segment (the client's SYN) consumes one byte; later segments
// advance by their payload length only.
func (s *TCPSimState) observeClientSeq(seq uint32, payloadLen int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.peerSeen {
		s.peerSeen = true
		s.peerISN = seq
		s.peerSeq = seq + 1 + uint32(payloadLen)
		return
	}
	s.peerSeq = seq + uint32(payloadLen)
}

// tsVal returns a plausible TCP timestamp value: milliseconds since a
// fixed epoch, so it grows monotonically like Linux jiffies.
func tsVal() uint32 {
	return uint32(time.Now().UnixMilli() & 0xFFFFFFFF)
}
