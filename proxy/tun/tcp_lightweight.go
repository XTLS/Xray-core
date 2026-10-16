package tun

import (
	"context"
	"encoding/binary"
	"io"
	"math"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

const (
	tcpFin = 1 << iota
	tcpSyn
	tcpRst
	tcpPsh
	tcpAck
)

const (
	// tcpWindow is what a connection takes from the system before its reader has to take it,
	// and the most that it sends to the system before that is acknowledged. More than that, for several
	// connections at once, is more packets than the queue of a tun holds (500 on Linux)
	tcpWindow = 256 << 10
	// tcpLargeWindow is the same for a tun that takes and gives segments that are larger than its MTU: those are
	// few, and a way with a longer round trip, as a router has to what is behind it, is not held back by it
	tcpLargeWindow = 1 << 20
	// tcpWindowShift makes them fit the 16 bits of a window
	tcpWindowShift = 5
	// tcpHeld is how many segments wait for one that was lost before them,
	// and of how many parts what the system says it has is known
	tcpHeld = 1024
	// tcpSmallest is the smallest mss that the system is believed, the one of Linux
	tcpSmallest = 48
	// tcpStamps is what the times of both sides take of the options of every segment that carries them (RFC 7323)
	tcpStamps = 12
	// tcpOpening is how many connections that the other side opens can be waiting for the answer to their SYN-ACK
	tcpOpening = 65535
	// tcpStart is how many segments are sent before any of them is acknowledged
	tcpStart = 10
	// tcpSegment is the largest payload of a segment that the tun splits by itself,
	// tcpParts of how many parts of what was written it is made at most
	tcpSegment = math.MaxUint16 - ipv6HeaderSize - tcpHeaderSize
	tcpParts   = 7
	// tcpKept is how large a payload is at least for the buffers that it was read into to be kept. A smaller one
	// is copied to where the one before it ends, for a reader to get buffers that are full
	tcpKept = buf.Size / 2

	// tcpTick is how often a connection that waits for something looks at what it waits for
	tcpTick = 100 * time.Millisecond
	// ticks without anything acknowledged before it is sent again, twice as many every next time, a minute at most,
	// while an open connection that waits sends again every two seconds at most or as often as an answer takes,
	// twice as seldom every next minute: when its way was away for a while it goes on soon after the way is back,
	// and the next segment still waits the doubled time, so that its answer can be timed
	tcpRetransmitTicks     = 3
	tcpRetransmitTicksOpen = 20
	tcpRetransmitTicksMost = 600
	tcpMinuteTicks         = int(time.Minute / tcpTick)
	// an open connection is given up after four minutes of ticks without an acknowledgment since the timer first sent
	// it again, as what is behind a wireless link may be away for a while (ticks, so that the time a computer sleeps
	// is not counted), and one that never answered after it was sent again that many times, after twenty seconds
	tcpGiveUpTicks    = 4 * tcpMinuteTicks
	tcpSynRetransmits = 5
	// ticks between the probes of a window that stays closed
	tcpProbeTicks = 10
	// tcpLinger is how long a closed connection waits for the system to close its side
	tcpLinger = 30 * time.Second
)

var (
	errTCPReset       = errors.New("connection reset")
	errTCPTimeout     = errors.New("connection timed out")
	errTCPRefused     = errors.New("connection refused")
	errTCPUnreachable = errors.New("destination unreachable")
)

// tcpStarted is where the times that segments carry count from
var tcpStarted = time.Now()

// segment is a TCP segment that came from the tun
type segment struct {
	seq, ack uint32
	flags    byte
	window   uint16
	options  []byte
	// payload is without its last rest bytes when those are in other buffers of the stack, see stack.whole
	payload []byte
	rest    int
}

// nextOption returns the first option of o and what follows it, kind is zero when there is none
func nextOption(o []byte) (kind byte, value, rest []byte) {
	for len(o) > 0 && o[0] == 1 {
		o = o[1:]
	}
	if len(o) < 2 || int(o[1]) < 2 || int(o[1]) > len(o) {
		return 0, nil, nil
	}
	return o[0], o[2:o[1]], o[o[1]:]
}

// held is a segment that came before the one in front of it
type held struct {
	seq  uint32
	data *buf.Buffer
}

// tcpConn is a TCP connection that the system opened through the tun, or one that was opened to it by DialTCP.
// Mostly the two are on the same machine, with nothing but the queue of the tun in between, which drops what
// does not fit. But the system may also pass on what others send, as a router does, and then the link to them
// is in between. So a connection has windows that are small enough, keeps what came after a lost segment,
// tells the system what it has (SACK), sends again what the system misses, and sends no more at once
// than what has arrived before (slow start and congestion avoidance as in RFC 5681)
type tcpConn struct {
	stack    *stack
	flow     flow
	src, dst net.Destination
	// ip is the IP header of what is sent, without the length
	ip [ipv6HeaderSize]byte
	// ipSize is the size of that header
	ipSize int
	// mss is the largest payload of a segment that is sent
	mss int
	// window is tcpWindow or tcpLargeWindow
	window int32
	// sndShift and rcvShift are the window scale of what the system and we advertise
	sndShift, rcvShift uint8
	// sack is set if the system takes selective acknowledgments
	sack bool
	// stamps is set if every segment carries the time of this side and the last one that came of the other side,
	// which sees by it how long its segments take, also the ones that it sent again (RFC 7323).
	// stampBase is what the time of this side starts from, stampSent the one that the last segment carried
	stamps               bool
	stampBase, stampSent uint32

	mu       sync.Mutex
	readable sync.Cond
	writable sync.Cond

	established bool
	// opened is there while DialTCP waits for the answer to its SYN, and closed when that wait is over
	opened chan struct{}
	// closed is set when Close is called
	closed bool
	// err is why the connection is gone
	err error

	rcvNxt uint32
	// rcvAcked is the last acknowledgment number sent
	rcvAcked uint32
	// rcvAdvertised is the last window sent, in bytes
	rcvAdvertised int32
	rcvQueue      buf.MultiBuffer
	rcvLen        int32
	rcvFin        bool
	// rcvEnd is where what the system sends ends, if rcvEnds: its FIN came with a segment that waits in rcvHeld
	rcvEnd  uint32
	rcvEnds bool
	// rcvHeld is what came after something that did not, in the order of seq and without overlaps
	rcvHeld []held
	// rcvLast is the seq of the last one that was put into rcvHeld
	rcvLast uint32
	// stamp is the time of the other side that is sent back to it
	stamp uint32

	sndUna, sndNxt uint32
	sndWnd         uint32
	// sndQueue is what was sent and is not acknowledged
	sndQueue buf.MultiBuffer
	// sndBase is the sequence number of the first byte of sndQueue
	sndBase uint32
	sndFin  bool
	// writing is how many of the last of sndQueue WriteMultiBuffer is sending, it is the only one to release them
	writing int
	// blocked is set while WriteMultiBuffer waits for the window
	blocked bool
	// sending is set while WriteMultiBuffer writes a segment without mu, ackWanted if sendAck was called meanwhile
	sending, ackWanted bool
	dupAcks            int
	// cwnd is how much the way to the system takes at once, as far as that is known: it grows while what is sent
	// arrives, by as much as arrives below ssthresh, and is cut when something is lost
	cwnd, ssthresh uint32
	// sacked is what the system says it has past sndUna, in order and apart from each other
	sacked [][2]uint32
	// recovering is set from a sign of loss until what was sent by then, up to recover, is acknowledged
	recovering bool
	recover    uint32
	// lost is the end of what is lost past the last of sacked, resent the end of what was sent again since then
	lost, resent uint32
	// headAt is when the segment at sndUna was sent again, or took that place while something was lost.
	// It is zero when that segment is not sent once more for the system still asking for it: it was already
	headAt time.Time
	// timed is the end of a segment that was sent at timedAt and not again, to see how long its acknowledgment takes.
	// The first one is the SYN-ACK
	timed   uint32
	timedAt time.Time
	// srtt is how long an acknowledgment takes, rttvar how much that varies (RFC 6298)
	srtt, rttvar time.Duration

	timer *time.Timer
	armed bool
	// stalled counts ticks without an acknowledgment of what waits for one
	stalled, retransmitTicks, retransmits int
	// lostTicks counts the ticks since the timer sent again the first time since something was acknowledged
	lostTicks int
	lingered  bool
}

func newTCPConn(s *stack, f flow) *tcpConn {
	c := &tcpConn{
		stack:           s,
		flow:            f,
		src:             net.TCPDestination(net.IPAddress(f.src.Addr().AsSlice()), net.Port(f.src.Port())),
		dst:             net.TCPDestination(net.IPAddress(f.dst.Addr().AsSlice()), net.Port(f.dst.Port())),
		window:          s.window,
		ssthresh:        uint32(s.window),
		timedAt:         time.Now(),
		retransmitTicks: tcpRetransmitTicks,
	}
	c.readable.L = &c.mu
	c.writable.L = &c.mu
	c.ipSize = putIPHeader(c.ip[:], protoTCP, f.dst.Addr(), f.src.Addr())
	c.mss = s.mtu - c.ipSize - tcpHeaderSize
	c.sndUna = rand.Uint32()
	c.sndNxt = c.sndUna + 1
	c.stampBase = rand.Uint32()
	return c
}

// synchronize takes what the SYN of the other side says. c.mu is held, or nobody else has c yet
func (c *tcpConn) synchronize(syn segment) {
	c.rcvNxt = syn.seq + 1
	c.sndWnd = uint32(syn.window)
	c.sack, c.stamps, c.sndShift, c.rcvShift = false, false, 0, 0
	for kind, value, o := nextOption(syn.options); kind != 0; kind, value, o = nextOption(o) {
		switch {
		case kind == 2 && len(value) == 2:
			c.mss = min(c.mss, int(binary.BigEndian.Uint16(value)))
		case kind == 3 && len(value) == 1:
			c.sndShift = min(value[0], 14)
			c.rcvShift = tcpWindowShift
		case kind == 4:
			c.sack = true
		case kind == 8 && len(value) == 8 && c.stack.stamps:
			c.stamps, c.stamp = true, binary.BigEndian.Uint32(value)
		}
	}
	if c.stamps {
		c.mss -= tcpStamps
	}
	c.mss = max(c.mss, tcpSmallest)
	c.cwnd = tcpStart * uint32(c.mss)
}

// DialTCP implements Stack
func (s *stack) DialTCP(ctx context.Context, remote netip.AddrPort) (net.Conn, error) {
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	local, err := s.local(remote.Addr())
	if err != nil {
		return nil, err
	}
	opened := make(chan struct{})
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, io.ErrClosedPipe
	}
	f := flow{src: remote}
	port, ok := ephemeral(func(port uint16) bool {
		f.dst = netip.AddrPortFrom(local, port)
		return s.conns[f] == nil
	})
	if !ok {
		s.mu.Unlock()
		return nil, errors.New("no port left to reach ", remote, " from")
	}
	f.dst = netip.AddrPortFrom(local, port)
	c := newTCPConn(s, f)
	// what the SYN offers, until the answer says what of it is taken
	c.sack, c.stamps, c.rcvShift, c.opened = true, s.stamps, tcpWindowShift, opened
	s.conns[f] = c
	s.mu.Unlock()
	s.opening.Add(1)
	c.mu.Lock()
	if c.err == nil {
		c.sendSyn()
		c.arm(tcpTick)
	}
	c.mu.Unlock()

	select {
	case <-opened:
	case <-ctx.Done():
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.established {
		if c.err == nil {
			c.abort(ctx.Err())
		}
		return nil, c.err
	}
	return c, nil
}

// header writes the headers of a segment with size bytes of payload into b and returns their size.
// The checksum of the segment is left to write. c.mu is held
func (c *tcpConn) header(b []byte, seq uint32, flags byte, options []byte, size int) int {
	n := copy(b, c.ip[:c.ipSize])
	stamps := 0
	if c.stamps {
		stamps = tcpStamps
	}
	t := b[n : n+tcpHeaderSize+stamps+len(options)]
	binary.BigEndian.PutUint16(t, c.flow.dst.Port())
	binary.BigEndian.PutUint16(t[2:], c.flow.src.Port())
	binary.BigEndian.PutUint32(t[4:], seq)
	binary.BigEndian.PutUint32(t[8:], c.rcvNxt)
	t[12] = byte(len(t)/4) << 4
	t[13] = flags
	window := max(c.window-c.rcvLen, 0)
	if flags&tcpSyn != 0 {
		// the window of a SYN is not scaled
		binary.BigEndian.PutUint16(t[14:], uint16(min(window, math.MaxUint16)))
	} else {
		binary.BigEndian.PutUint16(t[14:], uint16(min(window>>c.rcvShift, math.MaxUint16)))
	}
	t[16], t[17], t[18], t[19] = 0, 0, 0, 0
	if c.stamps {
		o := t[tcpHeaderSize:]
		o[0], o[1], o[2], o[3] = 1, 1, 8, 10
		if !c.sending {
			// what is sent while WriteMultiBuffer writes a segment has the time of that one: it may get to the tun
			// first, and the other side drops a segment with a time before the last one that it took
			c.stampSent = c.stampBase + uint32(time.Since(tcpStarted)/time.Millisecond)
		}
		binary.BigEndian.PutUint32(o[4:], c.stampSent)
		binary.BigEndian.PutUint32(o[8:], c.stamp)
	}
	copy(t[tcpHeaderSize+stamps:], options)
	setIPLength(b[:n], n+len(t)+size)
	c.rcvAcked = c.rcvNxt
	c.rcvAdvertised = window
	return n + len(t)
}

// write completes the headers h with the checksum of the segment and writes it to the tun.
// A segment that is not written is one that is lost: it is sent again when it is not acknowledged
func (c *tcpConn) write(h, payload []byte) {
	t := h[c.ipSize:]
	binary.BigEndian.PutUint16(t[16:], transportChecksum(h[:c.ipSize], protoTCP, t, payload))
	_ = c.stack.tun.WritePacket(h, payload)
}

// send writes a segment to the tun. c.mu is held
func (c *tcpConn) send(seq uint32, flags byte, options, payload []byte) {
	var b [ipv6HeaderSize + tcpHeaderSize + 40]byte
	c.write(b[:c.header(b[:], seq, flags, options, len(payload))], payload)
}

// sendSyn sends the answer to the SYN of the other side, or the SYN of a connection that is opened from here
func (c *tcpConn) sendSyn() {
	options := [12]byte{2, 4}
	binary.BigEndian.PutUint16(options[2:], uint16(c.stack.mtu-c.ipSize-tcpHeaderSize))
	n := 4
	if c.sack {
		n += copy(options[n:], []byte{1, 1, 4, 2})
	}
	if c.rcvShift != 0 {
		n += copy(options[n:], []byte{1, 3, 3, c.rcvShift})
	}
	flags := byte(tcpSyn | tcpAck)
	if c.opened != nil {
		flags = tcpSyn
	}
	c.send(c.sndUna, flags, options[:n], nil)
}

// sendAck acknowledges what was received, and tells what of rcvHeld waits for a lost segment
func (c *tcpConn) sendAck() {
	if c.sending {
		// after the segment that is being written: it was made before, and what the system is told goes in that order
		c.ackWanted = true
		return
	}
	if !c.sack || len(c.rcvHeld) == 0 {
		c.send(c.sndNxt, tcpAck, nil, nil)
		return
	}
	// the block with the segment that came last goes first. Next to the times there is room for one less
	var room [4][2]uint32
	blocks := room[:]
	if c.stamps {
		blocks = room[:3]
	}
	n, last := 1, false
	for i := 0; i < len(c.rcvHeld); {
		start, end, recent := c.rcvHeld[i].seq, c.rcvHeld[i].seq, false
		for ; i < len(c.rcvHeld) && c.rcvHeld[i].seq == end; i++ {
			recent = recent || end == c.rcvLast
			end += uint32(c.rcvHeld[i].data.Len())
		}
		if recent {
			blocks[0], last = [2]uint32{start, end}, true
		} else if n < len(blocks) {
			blocks[n] = [2]uint32{start, end}
			n++
		}
	}
	list := blocks[:n]
	if !last {
		list = list[1:]
	}
	options := [36]byte{1, 1, 5, byte(2 + 8*len(list))}
	for i, block := range list {
		binary.BigEndian.PutUint32(options[4+8*i:], block[0])
		binary.BigEndian.PutUint32(options[8+8*i:], block[1])
	}
	c.send(c.sndNxt, tcpAck, options[:4+8*len(list)], nil)
}

// stamped keeps the time that a segment of the other side carries, to send it back. It is the one of the segment
// that the stream goes on with, so that the other side sees how long that one took, and not one of what came
// before it. c.mu is held
func (c *tcpConn) stamped(s segment) {
	if int32(s.seq-c.rcvAcked) > 0 {
		return
	}
	for kind, value, o := nextOption(s.options); kind != 0; kind, value, o = nextOption(o) {
		if kind == 8 && len(value) == 8 {
			if stamp := binary.BigEndian.Uint32(value); int32(stamp-c.stamp) > 0 {
				c.stamp = stamp
			}
		}
	}
}

// input takes a segment of the connection. It returns false if the connection is gone
// and the segment is the start of another one
func (c *tcpConn) input(s segment) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return s.flags&(tcpSyn|tcpAck|tcpRst) != tcpSyn
	}
	if c.opened != nil {
		// only the answer to the SYN is waited for, or the word that nobody takes it
		switch {
		case s.flags&tcpAck == 0:
		case s.ack != c.sndNxt:
			// of a connection that the other side still has from before: it is told that there is none
			if s.flags&tcpRst == 0 {
				c.stack.refuse(c.flow, s)
			}
		case s.flags&tcpRst != 0:
			c.abort(errTCPRefused)
		case s.flags&tcpSyn != 0:
			c.synchronize(s)
			c.established = true
			c.sndUna, c.sndBase = s.ack, s.ack
			c.stalled, c.retransmits = 0, 0
			if !c.timedAt.IsZero() {
				c.clocked()
			}
			c.stack.opening.Add(-1)
			close(c.opened)
			c.opened = nil
			c.sendAck()
		}
		return true
	}
	if s.flags&tcpRst != 0 {
		// from where the system is, or was before its FIN, not from someone who knows no more than the addresses
		if s.seq-c.rcvNxt <= uint32(c.window) || c.rcvFin && s.seq+1 == c.rcvNxt {
			c.abort(errTCPReset)
		}
		return true
	}
	if s.flags&tcpSyn != 0 {
		switch {
		case !c.established && s.seq+1 == c.rcvNxt:
			c.sendSyn()
			c.timedAt = time.Time{}
		case c.closed && s.flags&tcpAck == 0 && !c.stack.verify:
			// the system of this machine opens the same ports again: it has let the old connection go.
			// What comes through a tunnel is answered with what is expected instead, as anyone who knows
			// the addresses could send it, and the other side answers that with a reset if it is gone
			c.abort(errTCPReset)
			return false
		default:
			c.sendAck()
		}
		return true
	}
	if s.flags&tcpAck == 0 {
		return true
	}
	if c.stamps {
		c.stamped(s)
	}
	if !c.established {
		if s.ack != c.sndNxt {
			return true
		}
		c.established = true
		c.sndUna = s.ack
		c.sndBase = s.ack
		c.sndWnd = uint32(s.window) << c.sndShift
		c.stalled, c.retransmits = 0, 0
		if !c.timedAt.IsZero() {
			c.clocked()
		}
		c.stack.opening.Add(-1)
		go c.stack.handle(c, c.dst)
	} else {
		c.acknowledge(s)
	}
	c.receive(s)
	if c.sndFin && c.rcvFin && c.sndUna == c.sndNxt {
		// both sides have closed it and nothing waits to be acknowledged
		c.abort(io.ErrClosedPipe)
	}
	return true
}

// acknowledge takes what a segment says about what was sent. c.mu is held
func (c *tcpConn) acknowledge(s segment) {
	acked, sent := s.ack-c.sndUna, c.sndNxt-c.sndUna
	if acked > sent {
		// older than the last one, or of what was not sent
		return
	}
	window := uint32(s.window) << c.sndShift
	if acked != 0 {
		c.sndUna = s.ack
		c.dupAcks, c.stalled, c.retransmits = 0, 0, 0
		c.release()
		n := 0
		for n < len(c.sacked) && int32(c.sacked[n][0]-c.sndUna) <= 0 {
			n++
		}
		c.sacked = slices.Delete(c.sacked, 0, n)
		if int32(c.resent-c.sndUna) < 0 {
			c.resent = c.sndUna
		}
		if !c.timedAt.IsZero() && int32(c.sndUna-c.timed) >= 0 {
			c.clocked()
		}
		recovering := c.recovering
		switch {
		case c.recovering && int32(c.sndUna-c.recover) >= 0:
			c.recovering = false
		case c.recovering:
			// what was sent again has arrived, and what was sent before it has not: the next segment is lost as well
			if end := c.sndUna + min(uint32(c.mss), c.recover-c.sndUna); int32(end-c.lost) > 0 {
				c.lost = end
			}
			c.headAt = time.Now()
		}
		// the way takes more if what it was given has arrived, as long as it was given about as much as it takes
		if sent >= c.cwnd/2 {
			if c.cwnd < c.ssthresh {
				grow := acked
				if recovering {
					// after a timeout: one segment that is sent again can acknowledge all that came after it,
					// which says nothing about how much the way takes at once
					grow = min(grow, 2*uint32(c.mss))
				}
				c.cwnd = min(c.cwnd+grow, c.ssthresh)
			} else if !c.recovering {
				// a segment more for every cwnd that arrives
				c.cwnd = min(c.cwnd+max(uint32(uint64(c.mss)*uint64(acked)/uint64(c.cwnd)), 1), uint32(c.window))
			}
		}
	} else if sent != 0 && window == c.sndWnd && len(s.payload) == 0 && s.flags&tcpFin == 0 {
		c.dupAcks++
	}
	if c.sack {
		for kind, value, o := nextOption(s.options); kind != 0; kind, value, o = nextOption(o) {
			for ; kind == 5 && len(value) >= 8; value = value[8:] {
				// of what was sent and is not acknowledged
				start, end := binary.BigEndian.Uint32(value)-c.sndUna, binary.BigEndian.Uint32(value[4:])-c.sndUna
				if start != 0 && start < end && end <= c.sndNxt-c.sndUna {
					c.sackAdd(c.sndUna+start, c.sndUna+end)
				}
			}
		}
	}
	if !c.recovering && c.sndUna != c.sndNxt && (len(c.sacked) > 0 || !c.sack && c.dupAcks >= 3) {
		// the system has something past sndUna, or says the same for the third time when it cannot say what it has:
		// the segment at sndUna is lost. One that can say it repeats itself also for what it got twice
		c.congested()
		c.lost = c.sndUna + min(uint32(c.mss), c.sndNxt-c.sndUna)
	}
	if c.recovering {
		if acked == 0 && c.srtt != 0 && !c.headAt.IsZero() && time.Since(c.headAt) > max(c.srtt+max(c.srtt/4, 4*c.rttvar), tcpTick/4) {
			// the segment that the system waits for was sent again longer ago than an answer takes, and the system
			// still answers what comes after it: that one was lost as well. It is sent once more, and only once:
			// the timer would find it too, but late, and then nothing is known anymore of how much the way takes
			if start, end := c.hole(c.sndUna); start == c.sndUna && start != end {
				c.retransmit(start, start+min(end-start, uint32(c.mss)))
				c.headAt, c.stalled = time.Time{}, 0
			}
		}
		c.resend()
	}
	c.sndWnd = window
	// the writer goes on when it can write a good part of the window, not for every segment that is acknowledged.
	// Unless the way to the system is what holds it back: that takes what the acknowledgments say has left it,
	// and what is sent as they come does not come to it all at once
	limit := min(c.sndWnd, uint32(c.window))
	enough := limit / 2
	if c.cwnd < limit {
		enough = uint32(c.mss)
	}
	if c.blocked && (c.sndUna == c.sndNxt || c.space() >= enough) {
		c.writable.Broadcast()
	}
}

// clocked takes the time since timedAt as how long an acknowledgment takes. The next ones are waited for as long
// as that says and no less than a few ticks. Until there is such a time again, after something was sent again,
// they are waited for as long as the last time. c.mu is held
func (c *tcpConn) clocked() {
	d := time.Since(c.timedAt)
	c.timedAt = time.Time{}
	if c.srtt == 0 {
		c.srtt, c.rttvar = d, d/2
	} else {
		c.rttvar += ((c.srtt - d).Abs() - c.rttvar) / 4
		c.srtt += (d - c.srtt) / 8
	}
	c.retransmitTicks = c.answerTicks()
}

// answerTicks is how many ticks an acknowledgment is waited for as long as nothing was sent again. c.mu is held
func (c *tcpConn) answerTicks() int {
	return max(tcpRetransmitTicks, int((c.srtt+4*c.rttvar)/tcpTick)+2)
}

// sackAdd puts what the system says it has into sacked. c.mu is held
func (c *tcpConn) sackAdd(start, end uint32) {
	i := 0
	for i < len(c.sacked) && int32(c.sacked[i][1]-start) < 0 {
		i++
	}
	j := i
	for ; j < len(c.sacked) && int32(c.sacked[j][0]-end) <= 0; j++ {
		if int32(c.sacked[j][0]-start) < 0 {
			start = c.sacked[j][0]
		}
		if int32(c.sacked[j][1]-end) > 0 {
			end = c.sacked[j][1]
		}
	}
	if i == j && len(c.sacked) == tcpHeld {
		return
	}
	c.sacked = slices.Replace(c.sacked, i, j, [2]uint32{start, end})
}

// congested is called when something is lost: the way to the system takes half of what it was given,
// and what is lost is sent again from sndUna. c.mu is held
func (c *tcpConn) congested() {
	c.ssthresh = max(min(c.cwnd, c.sndNxt-c.sndUna)/2, 2*uint32(c.mss))
	c.cwnd = c.ssthresh
	c.recovering, c.recover, c.resent = true, c.sndNxt, c.sndUna
	c.timedAt, c.headAt = time.Time{}, time.Time{}
}

// hole returns the first part at or after seq of what is lost: what the system does not have
// before something that it says it has, or before lost. There is none if it ends where it starts. c.mu is held
func (c *tcpConn) hole(seq uint32) (uint32, uint32) {
	end := c.lost
	for _, b := range c.sacked {
		if int32(b[0]-seq) > 0 {
			end = b[0]
			break
		}
		if int32(b[1]-seq) > 0 {
			seq = b[1]
		}
	}
	if int32(end-seq) < 0 {
		end = seq
	}
	return seq, end
}

// flight is how much of what was sent is on its way: not what the system says it has,
// and not what is lost and was not sent again. c.mu is held
func (c *tcpConn) flight() uint32 {
	n := c.sndNxt - c.sndUna
	if !c.recovering {
		return n
	}
	seq := c.resent
	for _, b := range c.sacked {
		n -= b[1] - b[0]
		if int32(b[0]-seq) > 0 {
			n -= b[0] - seq
		}
		if int32(b[1]-seq) > 0 {
			seq = b[1]
		}
	}
	if int32(c.lost-seq) > 0 {
		n -= c.lost - seq
	}
	return n
}

// resend sends again what is lost and was not yet: the segment that the system waits for at once,
// the rest as the way to it takes it. c.mu is held
func (c *tcpConn) resend() {
	for {
		start, end := c.hole(c.resent)
		if start == end {
			return
		}
		room := uint32(c.mss)
		if start != c.sndUna {
			flight := c.flight()
			if flight+room > c.cwnd {
				return
			}
			room = c.cwnd - flight
		}
		end = start + min(end-start, room)
		if start == c.sndUna {
			// its answer is waited for from now on
			c.headAt, c.stalled = time.Now(), 0
		}
		c.retransmit(start, end)
		c.resent = end
	}
}

// space is how much can be sent now: what the system takes, and what the way to it takes. c.mu is held
func (c *tcpConn) space() uint32 {
	window, sent, flight := min(c.sndWnd, uint32(c.window)), c.sndNxt-c.sndUna, c.flight()
	if sent >= window || flight >= c.cwnd {
		return 0
	}
	return min(window-sent, c.cwnd-flight)
}

// receive takes the payload of a segment. c.mu is held
func (c *tcpConn) receive(s segment) {
	// what is large, the next and all taken stays in the buffers that it was read into
	size := len(s.payload) + s.rest
	keep := c.stack.bufs != nil && size >= tcpKept && s.seq == c.rcvNxt && size <= int(c.window-c.rcvLen)
	if !keep {
		s.payload = c.stack.whole(s.payload, s.rest)
	}
	seq, payload, fin := s.seq, s.payload, s.flags&tcpFin != 0
	if len(payload) == 0 && !fin {
		if int32(c.rcvNxt-seq) > 0 {
			// a keepalive, or a probe of a window that the system has as closed: answered with what is expected
			c.sendAck()
		}
		return
	}
	if before := int32(c.rcvNxt - seq); before > 0 {
		if int(before) > len(payload) || int(before) == len(payload) && !fin {
			// sent again, or a keepalive: answered with what is expected
			c.sendAck()
			return
		}
		seq, payload = c.rcvNxt, payload[before:]
	}
	if c.rcvFin {
		c.sendAck()
		return
	}
	if c.closed && len(payload) > 0 {
		// nobody reads it anymore
		c.reset()
		return
	}
	// the system is told at once when something is wrong, or it sends more of the same
	now := len(c.rcvHeld) > 0
	if room := int(c.window - c.rcvLen - int32(seq-c.rcvNxt)); len(payload) > room {
		payload, fin, now = payload[:max(room, 0)], false, true
	}
	if seq != c.rcvNxt {
		// something before it was lost, it waits for that, and so does the end if this is it
		c.hold(seq, payload)
		if fin {
			c.rcvEnd, c.rcvEnds = seq+uint32(len(payload)), true
		}
		c.sendAck()
		return
	}

	if keep {
		c.rcvQueue = c.stack.keep(c.rcvQueue, payload, s.rest)
	} else {
		size = len(payload)
		c.rcvQueue = buf.MergeBytes(c.rcvQueue, payload)
	}
	c.rcvLen += int32(size)
	c.rcvNxt += uint32(size)
	for !fin && len(c.rcvHeld) > 0 && int32(c.rcvNxt-c.rcvHeld[0].seq) >= 0 {
		h := c.rcvHeld[0]
		if before := int32(c.rcvNxt - h.seq); before < h.data.Len() {
			c.rcvQueue = buf.MergeBytes(c.rcvQueue, h.data.BytesFrom(before))
			c.rcvLen += h.data.Len() - before
			c.rcvNxt += uint32(h.data.Len() - before)
		}
		h.data.Release()
		c.rcvHeld = c.rcvHeld[1:]
	}
	if fin = fin || c.rcvEnds && c.rcvNxt == c.rcvEnd; fin {
		c.rcvFin = true
		c.rcvNxt++
	}
	c.readable.Signal()
	// the reader acknowledges what it takes, with one segment for all that came by then.
	// It is not waited for when it does not read for long
	if fin || now || c.rcvNxt-c.rcvAcked >= uint32(c.window/4) {
		c.sendAck()
	} else {
		c.arm(tcpTick)
	}
}

// release releases what of sndQueue is acknowledged. c.mu is held
func (c *tcpConn) release() {
	for len(c.sndQueue) > c.writing {
		end := c.sndBase + uint32(c.sndQueue[0].Len())
		if int32(c.sndUna-end) < 0 {
			break
		}
		c.sndQueue[0].Release()
		c.sndQueue[0] = nil
		c.sndQueue = c.sndQueue[1:]
		c.sndBase = end
	}
}

// hold keeps a segment that is not the next one. c.mu is held
func (c *tcpConn) hold(seq uint32, payload []byte) {
	i := len(c.rcvHeld)
	for i > 0 && int32(c.rcvHeld[i-1].seq-seq) >= 0 {
		i--
	}
	// without what the one before and the one after have
	if i > 0 {
		if over := int32(c.rcvHeld[i-1].seq + uint32(c.rcvHeld[i-1].data.Len()) - seq); over > 0 {
			if int(over) >= len(payload) {
				return
			}
			seq, payload = seq+uint32(over), payload[over:]
		}
	}
	if i < len(c.rcvHeld) {
		if over := int32(seq + uint32(len(payload)) - c.rcvHeld[i].seq); over > 0 {
			if int(over) >= len(payload) {
				return
			}
			payload = payload[:len(payload)-int(over)]
		}
	}
	if len(payload) == 0 || len(c.rcvHeld) == tcpHeld {
		return
	}
	// as much memory as it carries: the room that is left counts bytes, and a thousand tiny segments in pooled
	// buffers would take two megabytes
	b := buf.FromBytes(slices.Clone(payload))
	c.rcvHeld = slices.Insert(c.rcvHeld, i, held{seq, b})
	c.rcvLast = seq
}

// retransmit sends again what was sent from seq to end. c.mu is held
func (c *tcpConn) retransmit(seq, end uint32) {
	fin := false
	if int32(end-c.sndNxt) >= 0 {
		end, fin = c.sndNxt, c.sndFin
		if fin {
			end--
		}
	}
	for int32(end-seq) > 0 {
		var part [1][]byte
		_, n := c.queued(part[:0], seq, min(c.mss, int(end-seq)))
		if n == 0 {
			break
		}
		c.send(seq, tcpAck, nil, part[0])
		seq += uint32(n)
	}
	if fin && seq == end {
		c.send(end, tcpFin|tcpAck, nil, nil)
	}
}

// queued adds to parts what of sndQueue starts at seq, size bytes at most and as many parts as it has room for,
// and returns them with their size. c.mu is held
func (c *tcpConn) queued(parts [][]byte, seq uint32, size int) ([][]byte, int) {
	skip, n := int32(seq-c.sndBase), 0
	for _, b := range c.sndQueue {
		if skip >= b.Len() {
			skip -= b.Len()
			continue
		}
		if n == size || len(parts) == cap(parts) {
			break
		}
		p := b.BytesFrom(skip)
		skip = 0
		p = p[:min(len(p), size-n)]
		parts = append(parts, p)
		n += len(p)
	}
	return parts, n
}

// shrink makes the segments fit a link on the way that takes packets of mtu bytes, when the one at seq did not.
// None of what is on its way fits: it is sent again, the first segment at once and the others as they are
// acknowledged. Only what is said about a segment that was sent and is not acknowledged is believed
func (c *tcpConn) shrink(seq uint32, mtu int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	mss := mtu - c.ipSize - tcpHeaderSize
	if c.stamps {
		mss -= tcpStamps
	}
	mss = max(mss, tcpSmallest)
	if c.err != nil || !c.established || seq-c.sndUna >= c.sndNxt-c.sndUna || mss >= c.mss {
		return
	}
	c.mss = mss
	// as what is lost, without the way taking less for it: it is the size that it did not take
	c.recovering, c.recover, c.lost = true, c.sndNxt, c.sndNxt
	c.timedAt = time.Time{}
	c.resent = c.sndUna + min(uint32(mss), c.sndNxt-c.sndUna)
	c.headAt = time.Now()
	c.retransmit(c.sndUna, c.resent)
}

// unreachable ends the wait for the answer to the SYN at seq, which a router on the way could not deliver
func (c *tcpConn) unreachable(seq uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err == nil && c.opened != nil && seq == c.sndUna {
		c.abort(errTCPUnreachable)
	}
}

// arm makes tick run after d, unless it is going to run already. c.mu is held
func (c *tcpConn) arm(d time.Duration) {
	if c.armed {
		return
	}
	c.armed = true
	if c.timer == nil {
		c.timer = time.AfterFunc(d, c.tick)
	} else {
		c.timer.Reset(d)
	}
}

// tick does what was put off and what has to be done again
func (c *tcpConn) tick() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.armed = false
	if c.err != nil {
		return
	}
	if c.rcvAcked != c.rcvNxt {
		c.sendAck()
	}
	switch {
	case c.sndUna != c.sndNxt:
		c.stalled++
		due := c.stalled >= c.retransmitTicks
		if c.established && c.retransmits > 0 {
			due = due || c.stalled >= max(tcpRetransmitTicksOpen, c.answerTicks())<<(c.lostTicks/tcpMinuteTicks)
		}
		if due {
			if c.retransmits++; c.retransmits == 1 {
				c.lostTicks = 0
			} else {
				c.lostTicks += c.stalled
			}
			if c.established && c.lostTicks > tcpGiveUpTicks || !c.established && c.retransmits > tcpSynRetransmits {
				c.abort(errTCPTimeout)
				return
			}
			c.stalled = 0
			c.retransmitTicks = min(c.retransmitTicks*2, tcpRetransmitTicksMost)
			if !c.established {
				c.sendSyn()
				c.timedAt = time.Time{}
			} else {
				// what the system does not say it has is lost, and the way to it is tried with a segment again.
				// It takes half of what it took before the loss, not half of that again if the loss was seen already
				ssthresh, recovering := c.ssthresh, c.recovering
				c.congested()
				if recovering {
					c.ssthresh = ssthresh
				}
				c.cwnd, c.lost = uint32(c.mss), c.sndNxt
				c.resend()
			}
		}
		c.arm(tcpTick)
	case c.blocked:
		// the segment that opens the window may have been lost, this one is answered with the window
		if c.stalled++; c.stalled%tcpProbeTicks == 0 {
			c.send(c.sndUna-1, tcpAck, nil, nil)
		}
		c.arm(tcpTick)
	case c.closed:
		if c.lingered {
			c.reset()
			return
		}
		c.lingered = true
		c.arm(tcpLinger)
	}
}

// reset tells the system that the connection is gone. c.mu is held
func (c *tcpConn) reset() {
	c.send(c.sndNxt, tcpRst|tcpAck, nil, nil)
	c.abort(io.ErrClosedPipe)
}

// abort ends the connection without another word to the system. What it has sent is still there to read.
// c.mu is held
func (c *tcpConn) abort(err error) {
	if c.err != nil {
		return
	}
	c.err = err
	if c.timer != nil {
		c.timer.Stop()
	}
	if c.opened != nil {
		close(c.opened)
		c.opened = nil
	}
	for _, h := range c.rcvHeld {
		h.data.Release()
	}
	c.rcvHeld = nil
	for _, b := range c.sndQueue[:len(c.sndQueue)-c.writing] {
		b.Release()
	}
	c.sndQueue = nil
	c.readable.Broadcast()
	c.writable.Broadcast()
	c.stack.remove(c)
}

// wait waits for something to read. c.mu is held
func (c *tcpConn) wait() error {
	for c.rcvLen == 0 && !c.rcvFin && !c.closed && c.err == nil {
		c.readable.Wait()
	}
	switch {
	case c.rcvLen > 0:
		return nil
	case c.err != nil && !c.rcvFin:
		return c.err
	}
	return io.EOF
}

// taken is called when size bytes have been read. c.mu is held
func (c *tcpConn) taken(size int32) {
	c.rcvLen -= size
	// the system may also have stopped at the window that it was told
	if c.err == nil && (c.rcvAcked != c.rcvNxt || c.rcvAdvertised < c.window/2) {
		c.sendAck()
	}
}

// ReadMultiBuffer implements buf.Reader
func (c *tcpConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.wait(); err != nil {
		return nil, err
	}
	mb := c.rcvQueue
	c.rcvQueue = nil
	c.taken(c.rcvLen)
	return mb, nil
}

// Read implements net.Conn
func (c *tcpConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.wait(); err != nil {
		return 0, err
	}
	var n int
	c.rcvQueue, n = buf.SplitBytes(c.rcvQueue, p)
	c.taken(int32(n))
	return n, nil
}

// WriteMultiBuffer implements buf.Writer. It is not called again before it returns
func (c *tcpConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	// without the empty ones
	n, size := 0, uint32(0)
	for _, b := range mb {
		if b.IsEmpty() {
			b.Release()
			continue
		}
		mb[n] = b
		n++
		size += uint32(b.Len())
	}
	mb = mb[:n]
	if c.err != nil || c.closed {
		buf.ReleaseMulti(mb)
		return io.ErrClosedPipe
	}
	// what is written is in sndQueue until it is acknowledged, and is not released before all of it is sent
	c.sndQueue = append(c.sndQueue, mb...)
	c.writing = len(mb)
	// a segment is one part of a Buffer, or as much as there is to send if the tun splits it by itself
	var room [tcpParts][]byte
	parts := room[:0:1]
	if c.stack.segmenter != nil {
		parts = room[:0]
	}
	for end := c.sndNxt + size; c.sndNxt != end; {
		// not a part of a segment when all of it can go later, with what is acknowledged by then
		for c.err == nil {
			if space := c.space(); space >= min(end-c.sndNxt, uint32(c.mss)) || space != 0 && c.sndUna == c.sndNxt {
				break
			}
			c.blocked = true
			c.arm(tcpTick)
			c.writable.Wait()
			c.blocked = false
		}
		if c.err != nil {
			break
		}
		// the mss may have become smaller while the last segment was written
		most := min(c.mss, int(c.space()))
		if c.stack.segmenter != nil {
			most = min(tcpSegment, int(c.space()))
		}
		if most > c.mss {
			// the same for what the tun splits
			most -= most % c.mss
		}
		p, n := c.queued(parts, c.sndNxt, most)
		flags := byte(tcpAck)
		if c.sndNxt+uint32(n) == end {
			flags |= tcpPsh
		}
		var b [ipv6HeaderSize + tcpHeaderSize + tcpStamps]byte
		h := b[:c.header(b[:], c.sndNxt, flags, nil, n)]
		if c.sndUna == c.sndNxt {
			// the ticks without an acknowledgment are counted from the first segment that waits for one
			c.stalled = 0
		}
		c.sndNxt += uint32(n)
		if c.timedAt.IsZero() {
			c.timed, c.timedAt = c.sndNxt, time.Now()
		}
		c.arm(tcpTick)
		// segments that come in the meantime are taken while this one is written, and acknowledged after it
		c.sending = true
		c.mu.Unlock()
		if s := c.stack.segmenter; s != nil {
			t := h[c.ipSize:]
			binary.BigEndian.PutUint16(t[16:], ^checksum(pseudoSum(h[:c.ipSize], protoTCP, len(t)+n)))
			_ = s.WriteSegment(h, p, c.mss)
		} else {
			c.write(h, p[0])
		}
		c.mu.Lock()
		c.sending = false
		if c.ackWanted && c.err == nil {
			c.sendAck()
		}
		c.ackWanted = false
	}
	c.writing = 0
	if c.err != nil {
		buf.ReleaseMulti(mb)
		return io.ErrClosedPipe
	}
	c.release()
	return nil
}

// Write implements net.Conn
func (c *tcpConn) Write(p []byte) (int, error) {
	if err := c.WriteMultiBuffer(buf.MergeBytes(nil, p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close implements net.Conn
func (c *tcpConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	unread := c.rcvLen > 0
	c.rcvQueue, c.rcvLen = buf.ReleaseMulti(c.rcvQueue), 0
	if c.err != nil {
		return nil
	}
	if unread || c.writing != 0 {
		// something was not read or not written, the system has to know
		c.reset()
		return nil
	}
	c.readable.Broadcast()
	c.send(c.sndNxt, tcpFin|tcpAck, nil, nil)
	c.sndFin = true
	c.sndNxt++
	c.arm(tcpTick)
	return nil
}

func (c *tcpConn) LocalAddr() net.Addr {
	return c.dst.RawNetAddr()
}

func (c *tcpConn) RemoteAddr() net.Addr {
	return c.src.RawNetAddr()
}

func (c *tcpConn) SetDeadline(time.Time) error {
	return nil
}

func (c *tcpConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *tcpConn) SetWriteDeadline(time.Time) error {
	return nil
}
