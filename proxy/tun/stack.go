package tun

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// Stack interface implement ip protocol stack, bridging raw network packets and data streams
type Stack interface {
	Start() error
	Close() error
}

// StackOptions for the stack implementation
type StackOptions struct {
	Tun         Tun
	MTU         uint32
	IdleTimeout time.Duration
}

// flow is what the packets of one connection have in common, src is the side of the system
type flow struct {
	src, dst netip.AddrPort
}

// stack turns the packets that the system sends to the tun into connections and back.
// It has only what the two need to talk through a tun, and a local link when the system passes on
// what others send, see tcpConn
type stack struct {
	ctx context.Context
	tun Tun
	mtu int
	// segmenter is the tun if it takes segments that are larger than its MTU
	segmenter segmenter
	// window is the window of every connection
	window int32
	// handle is given every new connection
	handle func(conn net.Conn, destination net.Destination)
	udp    *udpConnectionHandler

	mu     sync.Mutex
	conns  map[flow]*tcpConn
	closed bool
	// opening is how many of conns wait for the answer to their SYN-ACK
	opening atomic.Int32
}

// NewStack builds new ip stack
func NewStack(ctx context.Context, options StackOptions, handler *Handler) (Stack, error) {
	s := &stack{
		ctx:    ctx,
		tun:    options.Tun,
		mtu:    int(options.MTU),
		window: tcpWindow,
		handle: handler.HandleConnection,
		conns:  make(map[flow]*tcpConn),
	}
	if t, ok := options.Tun.(segmenter); ok && t.Segments() {
		s.segmenter = t
		s.window = tcpLargeWindow
	}
	s.udp = newUdpConnectionHandler(s.handle, s.writeUDP)
	return s, nil
}

// Start is called by Handler to bring stack to life
func (s *stack) Start() error {
	go s.read()
	return nil
}

// Close is called by Handler to shut down the stack
func (s *stack) Close() error {
	s.mu.Lock()
	s.closed = true
	conns := make([]*tcpConn, 0, len(s.conns))
	for _, c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		c.mu.Lock()
		if c.err == nil {
			c.reset()
		}
		c.mu.Unlock()
	}
	return nil
}

// read takes the packets of the tun until it is closed
func (s *stack) read() {
	// a tun that does not split segments gives them as large as a packet can be
	b := make([]byte, packetRoom+1<<16)
	for {
		b, err := s.tun.ReadPacket(b)
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if !closed {
				errors.LogErrorInner(s.ctx, err, "[tun] failed to read a packet, no more are read")
			}
			return
		}
		p, ok := parsePacket(b)
		if !ok {
			continue
		}
		switch p.proto {
		case protoTCP:
			s.handleTCP(p)
		case protoUDP:
			s.handleUDP(p)
		case protoICMPv4, protoICMPv6:
			s.handleICMP(p)
		}
	}
}

func (s *stack) handleTCP(p packet) {
	t := p.payload
	if len(t) < tcpHeaderSize {
		return
	}
	size := int(t[12]>>4) * 4
	if size < tcpHeaderSize || size > len(t) {
		return
	}
	f := flow{
		src: netip.AddrPortFrom(p.src, binary.BigEndian.Uint16(t)),
		dst: netip.AddrPortFrom(p.dst, binary.BigEndian.Uint16(t[2:])),
	}
	seg := segment{
		seq:     binary.BigEndian.Uint32(t[4:]),
		ack:     binary.BigEndian.Uint32(t[8:]),
		flags:   t[13],
		window:  binary.BigEndian.Uint16(t[14:]),
		options: t[tcpHeaderSize:size],
		payload: t[size:],
	}

	s.mu.Lock()
	c := s.conns[f]
	s.mu.Unlock()
	if c != nil && c.input(seg) {
		return
	}
	if seg.flags&(tcpSyn|tcpAck|tcpRst) != tcpSyn {
		if seg.flags&tcpRst == 0 {
			s.refuse(f, seg)
		}
		return
	}

	if s.opening.Load() >= tcpOpening {
		return
	}
	c = newTCPConn(s, f, seg)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.conns[f] = c
	s.mu.Unlock()
	s.opening.Add(1)
	c.mu.Lock()
	c.sendSynAck()
	c.arm(tcpTick)
	c.mu.Unlock()
}

// refuse answers a segment of a connection that is not known with a reset
func (s *stack) refuse(f flow, seg segment) {
	var b [ipv6HeaderSize + tcpHeaderSize]byte
	n := putIPHeader(b[:], protoTCP, f.dst.Addr(), f.src.Addr())
	t := b[n : n+tcpHeaderSize]
	binary.BigEndian.PutUint16(t, f.dst.Port())
	binary.BigEndian.PutUint16(t[2:], f.src.Port())
	t[12] = tcpHeaderSize / 4 << 4
	if seg.flags&tcpAck != 0 {
		binary.BigEndian.PutUint32(t[4:], seg.ack)
		t[13] = tcpRst
	} else {
		ack := seg.seq + uint32(len(seg.payload))
		if seg.flags&(tcpSyn|tcpFin) != 0 {
			ack++
		}
		binary.BigEndian.PutUint32(t[8:], ack)
		t[13] = tcpRst | tcpAck
	}
	setIPLength(b[:n], n+tcpHeaderSize)
	binary.BigEndian.PutUint16(t[16:], transportChecksum(b[:n], protoTCP, t, nil))
	_ = s.tun.WritePacket(b[:n+tcpHeaderSize], nil)
}

// remove forgets a connection. c.mu is held
func (s *stack) remove(c *tcpConn) {
	if !c.established {
		s.opening.Add(-1)
	}
	s.mu.Lock()
	if s.conns[c.flow] == c {
		delete(s.conns, c.flow)
	}
	s.mu.Unlock()
}

func (s *stack) handleUDP(p packet) {
	u := p.payload
	if len(u) < udpHeaderSize {
		return
	}
	size := int(binary.BigEndian.Uint16(u[4:]))
	if size < udpHeaderSize || size > len(u) {
		return
	}
	// the packet waits for its reader, longer than read keeps it
	b := buf.NewWithSize(int32(size - udpHeaderSize))
	b.Write(u[udpHeaderSize:size])
	src := net.UDPDestination(net.IPAddress(p.src.AsSlice()), net.Port(binary.BigEndian.Uint16(u)))
	dst := net.UDPDestination(net.IPAddress(p.dst.AsSlice()), net.Port(binary.BigEndian.Uint16(u[2:])))
	s.udp.HandlePacket(src, dst, b)
}

// writeUDP writes a packet with the payload from src to dst to the tun
func (s *stack) writeUDP(payload []byte, src net.Destination, dst net.Destination) error {
	srcIP, _ := netip.AddrFromSlice(src.Address.IP())
	dstIP, _ := netip.AddrFromSlice(dst.Address.IP())
	srcIP, dstIP = srcIP.Unmap(), dstIP.Unmap()
	if !srcIP.IsValid() || srcIP.Is4() != dstIP.Is4() {
		return errors.New("failed to write udp packet from ", src, " to ", dst)
	}
	var b [ipv6HeaderSize + udpHeaderSize]byte
	n := putIPHeader(b[:], protoUDP, srcIP, dstIP)
	u := b[n : n+udpHeaderSize]
	binary.BigEndian.PutUint16(u, uint16(src.Port))
	binary.BigEndian.PutUint16(u[2:], uint16(dst.Port))
	binary.BigEndian.PutUint16(u[4:], uint16(udpHeaderSize+len(payload)))
	setIPLength(b[:n], n+udpHeaderSize+len(payload))
	check := transportChecksum(b[:n], protoUDP, u, payload)
	if check == 0 {
		// zero stands for no checksum
		check = 0xffff
	}
	binary.BigEndian.PutUint16(u[6:], check)
	return s.tun.WritePacket(b[:n+udpHeaderSize], payload)
}

// handleICMP answers an echo request as its destination would
func (s *stack) handleICMP(p packet) {
	m := p.payload
	request, reply := byte(8), byte(0)
	if p.proto == protoICMPv6 {
		request, reply = 128, 129
	}
	if len(m) < 8 || m[0] != request || m[1] != 0 {
		return
	}
	var b [ipv6HeaderSize]byte
	n := putIPHeader(b[:], p.proto, p.dst, p.src)
	setIPLength(b[:n], n+len(m))
	// the reply is the request with another type
	m[0], m[2], m[3] = reply, 0, 0
	if p.proto == protoICMPv6 {
		binary.BigEndian.PutUint16(m[2:], transportChecksum(b[:n], protoICMPv6, m, nil))
	} else {
		binary.BigEndian.PutUint16(m[2:], checksum(sum(m, 0)))
	}
	_ = s.tun.WritePacket(b[:n], m)
}
