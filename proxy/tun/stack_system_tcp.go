package tun

import (
	"io"
	"sync"
	"time"

	xerrors "github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

// This file implements a small, dedicated TCP state machine for the "system"
// tun stack, see stack_system.go. It intentionally does not implement window
// scaling, SACK, timestamps, congestion control, fast retransmit or
// out-of-order reassembly: the tun channel only ever carries packets produced
// by the local OS network stack and handed to us directly, so it neither
// reorders nor drops them the way the public internet does; a single RTO
// timer (also used for zero-window probing) is enough to make the connection
// robust against the rare occasions a segment does not make it through.
const (
	minRTO         = 300 * time.Millisecond
	maxRTO         = 30 * time.Second
	maxRTORetries  = 12
	lingerDuration = 5 * time.Second

	// maxSendBuffer/maxRecvBuffer match the gVisor backend's own default
	// buffer sizes (tcp.DefaultSendBufferSize/DefaultReceiveBufferSize), so
	// switching between backends does not change buffering expectations.
	maxSendBuffer = 1 << 20
	maxRecvBuffer = 1 << 20
)

var (
	errStackClosed     = xerrors.New("tun stack closed")
	errConnReset       = xerrors.New("connection reset by peer")
	errConnClosed      = xerrors.New("use of closed network connection")
	errConnIdleTimeout = xerrors.New("connection idle timeout")
	errConnTimedOut    = xerrors.New("connection timed out")
)

type tcpState uint8

const (
	stateSynRcvd tcpState = iota
	stateEstablished
	stateCloseWait // peer's FIN was received; we may still send until we close too
	stateClosing   // our FIN was sent (from Established or CloseWait)
	stateTimeWait  // both FINs exchanged and acked; short linger before removal
	stateClosed    // terminal, removed from the connection table
)

// tcpKey identifies a tcp connection the same way it appears on the wire
// flowing from the app behind the tun device towards its destination.
type tcpKey struct {
	netProto tcpip.NetworkProtocolNumber
	srcAddr  tcpip.Address
	srcPort  uint16
	dstAddr  tcpip.Address
	dstPort  uint16
}

// tcpConn is a minimal TCP endpoint implementing net.Conn. It deliberately
// exposes only plain Read/Write (never ReadMultiBuffer/WriteMultiBuffer) so
// that stat.CounterConnection in handler.go keeps accounting traffic
// correctly, matching the udpConn precedent in udp_fullcone.go.
type tcpConn struct {
	stack *stackSystem
	key   tcpKey
	src   net.Destination
	dst   net.Destination

	ourMSS int

	mu   sync.Mutex
	cond *sync.Cond

	state tcpState

	// send side. sendQueue[0] always holds the byte at sequence sndUna: acked
	// bytes are trimmed off the front, so no separate "acked" bookkeeping is
	// needed. sendQueue[:unsentOffset] has been transmitted at least once;
	// sendQueue[unsentOffset:] never has.
	iss          seqnum.Value
	sndUna       seqnum.Value
	sndNxt       seqnum.Value
	sndMSS       int
	peerWindow   uint32
	sendQueue    []byte
	unsentOffset int
	closeCalled  bool
	finSent      bool
	finAcked     bool
	finSeq       seqnum.Value

	// receive side.
	irs          seqnum.Value
	rcvNxt       seqnum.Value
	recvQueue    [][]byte
	recvOffset   int
	recvBuffered int
	recvClosed   bool

	err error

	lastActive time.Time

	rtoTimer    *time.Timer
	rtoBackoff  int
	lingerTimer *time.Timer
}

var _ net.Conn = (*tcpConn)(nil)

// outgoingMSS returns the MSS we can use without ever needing IP
// fragmentation (unsupported), given the tun device's MTU.
func outgoingMSS(mtu uint32, netProto tcpip.NetworkProtocolNumber) int {
	ipHdrSize := header.IPv4MinimumSize
	if netProto == header.IPv6ProtocolNumber {
		ipHdrSize = header.IPv6MinimumSize
	}
	mss := int(mtu) - ipHdrSize - header.TCPMinimumSize
	const minMSS = 88
	if mss < minMSS {
		mss = minMSS
	}
	return mss
}

// handleTCP is the tcp entry point from stackSystem.handleTransport.
func (s *stackSystem) handleTCP(netProto tcpip.NetworkProtocolNumber, srcIP, dstIP tcpip.Address, payload []byte) {
	if len(payload) < header.TCPMinimumSize {
		return
	}
	tcpHdr := header.TCP(payload)
	if _, _, ok := header.TCPValid(tcpHdr, nil, 0, tcpip.Address{}, tcpip.Address{}, true); !ok {
		return
	}

	key := tcpKey{
		netProto: netProto,
		srcAddr:  srcIP,
		srcPort:  tcpHdr.SourcePort(),
		dstAddr:  dstIP,
		dstPort:  tcpHdr.DestinationPort(),
	}

	s.tcpMu.Lock()
	conn, ok := s.tcp[key]
	s.tcpMu.Unlock()

	if ok {
		conn.handleSegment(tcpHdr)
		return
	}

	flags := tcpHdr.Flags()
	if flags&header.TCPFlagRst != 0 {
		return // never generate a reset in response to a reset
	}
	if flags&header.TCPFlagSyn != 0 && flags&header.TCPFlagAck == 0 {
		s.newTCPConn(key, tcpHdr)
		return
	}

	// any other segment referencing an unknown connection: let the peer know
	// promptly it no longer/never existed, same as a real kernel would
	s.sendRawTCPReset(key, tcpHdr)
}

func (s *stackSystem) newTCPConn(key tcpKey, tcpHdr header.TCP) {
	synOpts := header.ParseSynOptions(tcpHdr.Options(), false)

	c := &tcpConn{
		stack: s,
		key:   key,
		src:   net.TCPDestination(net.IPAddress(key.srcAddr.AsSlice()), net.Port(key.srcPort)),
		dst:   net.TCPDestination(net.IPAddress(key.dstAddr.AsSlice()), net.Port(key.dstPort)),
		state: stateSynRcvd,
	}
	c.cond = sync.NewCond(&c.mu)

	c.iss = randomSequenceNumber()
	c.sndUna = c.iss
	c.sndNxt = c.iss.Add(1)

	c.irs = seqnum.Value(tcpHdr.SequenceNumber())
	c.rcvNxt = c.irs.Add(1)

	c.ourMSS = outgoingMSS(s.mtu, key.netProto)
	c.sndMSS = int(synOpts.MSS)
	if c.sndMSS <= 0 || c.sndMSS > c.ourMSS {
		c.sndMSS = c.ourMSS
	}
	c.lastActive = time.Now()

	s.tcpMu.Lock()
	s.tcp[key] = c
	s.tcpMu.Unlock()

	c.mu.Lock()
	c.sendSynAckLocked()
	c.mu.Unlock()
}

// sendRawTCPReset replies to a segment that does not match any known
// connection, following the rules of RFC 9293 §3.10.7.1.
func (s *stackSystem) sendRawTCPReset(key tcpKey, tcpHdr header.TCP) {
	flags := tcpHdr.Flags()
	segLen := seqnum.Size(len(tcpHdr.Payload()))
	if flags&header.TCPFlagSyn != 0 {
		segLen++
	}
	if flags&header.TCPFlagFin != 0 {
		segLen++
	}

	var seq, ack seqnum.Value
	var ackFlag header.TCPFlags
	if flags&header.TCPFlagAck != 0 {
		seq = seqnum.Value(tcpHdr.AckNumber())
	} else {
		ack = seqnum.Value(tcpHdr.SequenceNumber()).Add(segLen)
		ackFlag = header.TCPFlagAck
	}

	segment := make([]byte, header.TCPMinimumSize)
	rst := header.TCP(segment)
	rst.Encode(&header.TCPFields{
		SrcPort:    key.dstPort,
		DstPort:    key.srcPort,
		SeqNum:     uint32(seq),
		AckNum:     uint32(ack),
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagRst | ackFlag,
		WindowSize: 0,
	})
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, key.dstAddr, key.srcAddr, uint16(len(segment)))
	rst.SetChecksum(^rst.CalculateChecksum(xsum))

	if err := s.writeTransportSegment(key.netProto, header.TCPProtocolNumber, key.dstAddr, key.srcAddr, segment); err != nil {
		xerrors.LogInfoInner(s.ctx, err, "[tun] failed to write tcp reset")
	}
}

func (c *tcpConn) lastActiveTime() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastActive
}

// abort is the externally callable (unlocked) equivalent of abortLocked,
// used by the idle reaper and by Close's callers indirectly through it.
func (c *tcpConn) abort(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.abortLocked(err)
}

func (c *tcpConn) abortLocked(err error) {
	if c.state == stateClosed {
		return
	}
	c.state = stateClosed
	c.stopRTOLocked()
	c.stopLingerLocked()
	c.err = err
	c.cond.Broadcast()
	// deliberately does not send an RST: if the peer sends anything else for
	// this connection later, it will miss the (now removed) table entry and
	// get a fresh, correctly-addressed reset from sendRawTCPReset above.
	c.stack.removeTCPConn(c.key, c)
}

// handleSegment processes one already-demultiplexed incoming segment.
func (c *tcpConn) handleSegment(tcpHdr header.TCP) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == stateClosed {
		return
	}
	c.lastActive = time.Now()

	flags := tcpHdr.Flags()

	if flags&header.TCPFlagRst != 0 {
		c.abortLocked(errConnReset)
		return
	}

	if c.state == stateSynRcvd {
		c.handleSynRcvdSegmentLocked(tcpHdr)
		return
	}

	if flags&header.TCPFlagSyn != 0 {
		// unexpected SYN on an already-established connection is not
		// modeled; treat it like the peer abandoned and reset it
		c.abortLocked(errConnReset)
		return
	}

	if flags&header.TCPFlagAck != 0 {
		c.handleAckLocked(seqnum.Value(tcpHdr.AckNumber()), tcpHdr.WindowSize())
	}

	c.acceptInOrderLocked(seqnum.Value(tcpHdr.SequenceNumber()), tcpHdr.Payload(), flags&header.TCPFlagFin != 0)
}

func (c *tcpConn) handleSynRcvdSegmentLocked(tcpHdr header.TCP) {
	flags := tcpHdr.Flags()

	if flags&header.TCPFlagSyn != 0 {
		// peer's retransmission of the original SYN, our SYN-ACK likely
		// hasn't reached them yet: resend it and rely entirely on their own
		// retransmission timer rather than running one on our side too
		c.sendSynAckLocked()
		return
	}
	if flags&header.TCPFlagAck == 0 {
		return
	}
	if seqnum.Value(tcpHdr.AckNumber()) != c.sndNxt {
		// does not acknowledge our SYN correctly; a well-behaved peer will
		// simply retry, so it is safe to just ignore this segment
		return
	}

	c.state = stateEstablished
	go c.stack.handler.HandleConnection(c, c.dst)

	c.handleAckLocked(seqnum.Value(tcpHdr.AckNumber()), tcpHdr.WindowSize())
	c.acceptInOrderLocked(seqnum.Value(tcpHdr.SequenceNumber()), tcpHdr.Payload(), flags&header.TCPFlagFin != 0)
}

// acceptInOrderLocked handles the data/FIN portion of a segment once it is
// known to be neither a SYN nor a RST. Only strictly in-order segments are
// accepted; anything else is dropped (relying on the peer's retransmission)
// since the tun channel is expected to already deliver packets in order.
func (c *tcpConn) acceptInOrderLocked(seq seqnum.Value, payload []byte, fin bool) {
	if seq != c.rcvNxt {
		c.sendAckLocked()
		return
	}

	accept := payload
	if room := c.recvWindowLocked(); uint32(len(accept)) > room {
		accept = accept[:room]
	}
	if len(accept) > 0 {
		c.enqueueRecvLocked(accept)
		c.rcvNxt = c.rcvNxt.Add(seqnum.Size(len(accept)))
	}

	finAccepted := false
	if fin && len(accept) == len(payload) {
		c.onFinLocked()
		c.rcvNxt = c.rcvNxt.Add(1)
		finAccepted = true
	}

	if len(accept) > 0 || finAccepted || len(accept) < len(payload) {
		c.sendAckLocked()
	}
}

func (c *tcpConn) onFinLocked() {
	if c.recvClosed {
		return
	}
	c.recvClosed = true
	c.cond.Broadcast()
	if c.state == stateEstablished {
		c.state = stateCloseWait
	}
	c.maybeFinishCloseLocked()
}

func (c *tcpConn) handleAckLocked(ackNum seqnum.Value, windowSize uint16) {
	if ackNum.LessThan(c.sndUna) {
		// old/duplicate ack: no fast-retransmit heuristics implemented
		c.peerWindow = uint32(windowSize)
		c.trySendLocked()
		return
	}
	if c.sndNxt.LessThan(ackNum) {
		// acknowledges more than we ever sent: lenient clamp instead of
		// rejecting the segment outright
		ackNum = c.sndNxt
	}

	if advanced := c.sndUna.Size(ackNum); advanced > 0 {
		c.sndUna = ackNum
		n := int(advanced)
		if n > len(c.sendQueue) {
			n = len(c.sendQueue)
		}
		c.sendQueue = c.sendQueue[n:]
		c.unsentOffset -= n
		if c.unsentOffset < 0 {
			c.unsentOffset = 0
		}
		c.rtoBackoff = 0
		if c.finSent && c.sndUna == c.sndNxt {
			c.finAcked = true
		}
		c.cond.Broadcast()
	}

	c.peerWindow = uint32(windowSize)
	c.trySendLocked()
	c.maybeFinishCloseLocked()
}

func (c *tcpConn) maybeFinishCloseLocked() {
	if c.state == stateClosing && c.finAcked && c.recvClosed {
		c.state = stateTimeWait
		c.startLingerLocked()
	}
}

func (c *tcpConn) recvWindowLocked() uint32 {
	room := maxRecvBuffer - c.recvBuffered
	if room < 0 {
		room = 0
	}
	if room > 0xffff {
		room = 0xffff
	}
	return uint32(room)
}

func (c *tcpConn) enqueueRecvLocked(payload []byte) {
	data := make([]byte, len(payload))
	copy(data, payload)
	c.recvQueue = append(c.recvQueue, data)
	c.recvBuffered += len(data)
	c.cond.Broadcast()
}

// sendOneChunkLocked transmits up to maxLen bytes of never-yet-sent data (if
// any remains), advancing sndNxt/unsentOffset. It returns the number of
// bytes sent, 0 if none remained.
func (c *tcpConn) sendOneChunkLocked(maxLen int) int {
	remaining := len(c.sendQueue) - c.unsentOffset
	if remaining <= 0 {
		return 0
	}
	if maxLen > remaining {
		maxLen = remaining
	}
	if maxLen > c.sndMSS {
		maxLen = c.sndMSS
	}
	if maxLen <= 0 {
		return 0
	}
	data := c.sendQueue[c.unsentOffset : c.unsentOffset+maxLen]
	c.sendDataSegmentLocked(c.sndNxt, data, false)
	c.sndNxt = c.sndNxt.Add(seqnum.Size(maxLen))
	c.unsentOffset += maxLen
	return maxLen
}

func (c *tcpConn) trySendLocked() {
	switch c.state {
	case stateSynRcvd, stateTimeWait, stateClosed:
		return
	}

	for {
		inFlight := int(c.sndUna.Size(c.sndNxt))
		windowLeft := int(c.peerWindow) - inFlight
		if windowLeft <= 0 {
			break
		}
		if c.sendOneChunkLocked(windowLeft) == 0 {
			break
		}
	}

	if c.closeCalled && !c.finSent && c.unsentOffset == len(c.sendQueue) {
		c.finSeq = c.sndNxt
		c.sendDataSegmentLocked(c.finSeq, nil, true)
		c.sndNxt = c.sndNxt.Add(1)
		c.finSent = true
	}

	c.refreshRTOLocked()
}

func (c *tcpConn) outstandingLocked() bool {
	if c.unsentOffset > 0 {
		return true // already-transmitted data pending ack
	}
	if len(c.sendQueue) > c.unsentOffset && c.peerWindow == 0 {
		return true // blocked purely by a zero window; need to probe
	}
	if c.finSent && !c.finAcked {
		return true // FIN transmitted but not yet acked
	}
	return false
}

func (c *tcpConn) refreshRTOLocked() {
	if c.outstandingLocked() {
		c.scheduleRTOLocked()
	} else {
		c.stopRTOLocked()
	}
}

func (c *tcpConn) rtoDurationLocked() time.Duration {
	d := minRTO * time.Duration(uint64(1)<<uint(c.rtoBackoff))
	if d > maxRTO || d <= 0 {
		d = maxRTO
	}
	return d
}

func (c *tcpConn) scheduleRTOLocked() {
	d := c.rtoDurationLocked()
	if c.rtoTimer == nil {
		c.rtoTimer = time.AfterFunc(d, c.onRTOTimerFired)
	} else {
		c.rtoTimer.Reset(d)
	}
}

func (c *tcpConn) stopRTOLocked() {
	if c.rtoTimer != nil {
		c.rtoTimer.Stop()
	}
}

func (c *tcpConn) onRTOTimerFired() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onRTOFireLocked()
}

func (c *tcpConn) onRTOFireLocked() {
	if c.state == stateClosed || !c.outstandingLocked() {
		return
	}
	if c.rtoBackoff >= maxRTORetries {
		c.abortLocked(errConnTimedOut)
		return
	}
	c.rtoBackoff++

	switch {
	case c.unsentOffset > 0:
		c.sendDataSegmentLocked(c.sndUna, c.sendQueue[:c.unsentOffset], false)
	case len(c.sendQueue) > c.unsentOffset:
		// nothing in flight, but blocked by a zero peer window: probe with
		// exactly one new byte, per RFC 9293 §3.8.6.1
		c.sendOneChunkLocked(1)
	case c.finSent && !c.finAcked:
		c.sendDataSegmentLocked(c.finSeq, nil, true)
	}

	c.refreshRTOLocked()
}

func (c *tcpConn) startLingerLocked() {
	c.stopRTOLocked()
	c.lingerTimer = time.AfterFunc(lingerDuration, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.abortLocked(errConnClosed)
	})
}

func (c *tcpConn) stopLingerLocked() {
	if c.lingerTimer != nil {
		c.lingerTimer.Stop()
	}
}

// transmitLocked builds, checksums and writes a single tcp segment.
func (c *tcpConn) transmitLocked(seq, ack seqnum.Value, flags header.TCPFlags, payload []byte, options []byte) {
	headerLen := header.TCPMinimumSize + len(options)
	segment := make([]byte, headerLen+len(payload))
	tcpHdr := header.TCP(segment)
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    c.key.dstPort,
		DstPort:    c.key.srcPort,
		SeqNum:     uint32(seq),
		AckNum:     uint32(ack),
		DataOffset: uint8(headerLen),
		Flags:      flags,
		WindowSize: uint16(c.recvWindowLocked()),
	})
	copy(tcpHdr.Options(), options)
	copy(segment[headerLen:], payload)

	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, c.key.dstAddr, c.key.srcAddr, uint16(len(segment)))
	xsum = checksum.Checksum(payload, xsum)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(xsum))

	if err := c.stack.writeTransportSegment(c.key.netProto, header.TCPProtocolNumber, c.key.dstAddr, c.key.srcAddr, segment); err != nil {
		xerrors.LogInfoInner(c.stack.ctx, err, "[tun] failed to write tcp segment")
	}
}

func (c *tcpConn) sendSynAckLocked() {
	var optBuf [header.TCPOptionMSSLength]byte
	n := header.EncodeMSSOption(uint32(c.ourMSS), optBuf[:])
	c.transmitLocked(c.iss, c.rcvNxt, header.TCPFlagSyn|header.TCPFlagAck, nil, optBuf[:n])
}

func (c *tcpConn) sendAckLocked() {
	c.transmitLocked(c.sndNxt, c.rcvNxt, header.TCPFlagAck, nil, nil)
}

func (c *tcpConn) sendDataSegmentLocked(seq seqnum.Value, payload []byte, fin bool) {
	flags := header.TCPFlagAck
	if fin {
		flags |= header.TCPFlagFin
	}
	c.transmitLocked(seq, c.rcvNxt, flags, payload, nil)
}

// Read implements net.Conn.
func (c *tcpConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for len(c.recvQueue) == 0 && c.err == nil && !c.recvClosed {
		c.cond.Wait()
	}
	if c.err != nil {
		return 0, c.err
	}
	if len(c.recvQueue) == 0 {
		return 0, io.EOF
	}

	before := c.recvWindowLocked()

	chunk := c.recvQueue[0]
	n := copy(p, chunk[c.recvOffset:])
	c.recvOffset += n
	c.recvBuffered -= n
	if c.recvOffset == len(chunk) {
		c.recvQueue = c.recvQueue[1:]
		c.recvOffset = 0
	}

	// let the peer know promptly if reading just freed up a previously
	// exhausted window, instead of waiting for it to probe us for an update
	if after := c.recvWindowLocked(); before == 0 && after > 0 {
		c.sendAckLocked()
	}

	return n, nil
}

// Write implements net.Conn.
func (c *tcpConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closeCalled {
		return 0, errConnClosed
	}

	total := 0
	for total < len(p) {
		if c.err != nil {
			return total, c.err
		}
		if c.closeCalled {
			return total, errConnClosed
		}
		room := maxSendBuffer - len(c.sendQueue)
		if room <= 0 {
			c.cond.Wait()
			continue
		}
		n := len(p) - total
		if n > room {
			n = room
		}
		c.sendQueue = append(c.sendQueue, p[total:total+n]...)
		total += n
	}

	c.trySendLocked()
	return total, nil
}

// Close implements net.Conn.
func (c *tcpConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closeCalled {
		return nil
	}
	c.closeCalled = true
	c.cond.Broadcast()

	switch c.state {
	case stateEstablished, stateCloseWait:
		c.state = stateClosing
	default:
		return nil
	}

	c.trySendLocked()
	return nil
}

func (c *tcpConn) LocalAddr() net.Addr  { return c.dst.RawNetAddr() }
func (c *tcpConn) RemoteAddr() net.Addr { return c.src.RawNetAddr() }

func (c *tcpConn) SetDeadline(t time.Time) error      { return nil }
func (c *tcpConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *tcpConn) SetWriteDeadline(t time.Time) error { return nil }
