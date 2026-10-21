package tun

import (
	"context"
	"encoding/binary"
	"io"
	"math"
	"math/rand/v2"
	gonet "net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// Stack interface implement ip protocol stack, bridging raw network packets and data streams
type Stack interface {
	// Start makes the stack read the packets of its tun
	Start() error
	Close() error
	// Input takes a packet of a tun that hands them over instead of being read. The packet is not kept,
	// but it may be written to. The packets of one connection have to come one after another
	Input(packet []byte)
	// DialTCP opens a connection to address from the one of StackOptions.Addresses that is of its family
	DialTCP(ctx context.Context, address netip.AddrPort) (net.Conn, error)
	// DialUDP opens a port on StackOptions.Addresses. What anyone sends to the port is read from it
	DialUDP() (net.PacketConn, error)
}

// StackOptions for the stack implementation
type StackOptions struct {
	Tun         Tun
	MTU         uint32
	IdleTimeout time.Duration
	// Addresses are what the stack opens connections from
	Addresses []netip.Addr
	// Remote is set if the tun is a tunnel to another system and not the tun of this one: what comes through it
	// has come a long way, so its checksums are looked at, nothing but that way limits the windows, and the
	// segments of TCP carry the times of both sides if the other side has them
	Remote bool
}

// flow is what the packets of one connection have in common, src is the side of the system
type flow struct {
	src, dst netip.AddrPort
}

// stack turns the packets that the system sends to the tun into connections and back.
// It has only what the two need to talk through a tun, and a local link when the system passes on
// what others send, see tcpConn. The tun may also be a tunnel to a system that is far away, and the stack
// the one that opens the connections
type stack struct {
	ctx context.Context
	tun Tun
	mtu int
	// segmenter is the tun if it takes segments that are larger than its MTU
	segmenter segmenter
	// window is the window of every connection
	window int32
	// verify is set if the checksums of what comes are looked at
	verify bool
	// stamps is set if connections carry the times of RFC 7323 when the other side does
	stamps bool
	// handle is given every new connection that the other side opens. Without it those are refused
	handle func(conn net.Conn, destination net.Destination)
	udp    *udpConnectionHandler
	// addresses are what connections are opened from
	addresses []netip.Addr
	// bufs is what read reads a packet into if the tun is a segmenter, one after the other, the headers in the first.
	// One that keep took is nil. joined is for a packet that is in more than one and is needed in one piece
	bufs   buf.MultiBuffer
	joined []byte

	mu    sync.Mutex
	conns map[flow]*tcpConn
	// sockets are the ports that DialUDP has opened
	sockets map[netip.AddrPort]*udpSocket
	closed  bool
	// opening is how many of conns wait for the answer to their SYN or SYN-ACK
	opening atomic.Int32
	// fragments are the packets that are larger than a link on their way and come in parts.
	// identification numbers the ones that leave like that: a counter for each of a few groups of destinations,
	// each from a start of its own, so that no two of them that go one way meet, and no destination learns how much
	// goes to the others
	fragments      reassembly
	identification [64]atomic.Uint32
}

// NewStack builds new ip stack. Without a handler it takes no connections, only opens them
func NewStack(ctx context.Context, options StackOptions, handler ConnectionHandler) (Stack, error) {
	s := &stack{
		ctx:       ctx,
		tun:       options.Tun,
		mtu:       int(options.MTU),
		window:    tcpWindow,
		addresses: options.Addresses,
		verify:    options.Remote,
		stamps:    options.Remote,
		conns:     make(map[flow]*tcpConn),
		sockets:   make(map[netip.AddrPort]*udpSocket),
	}
	if t, ok := options.Tun.(segmenter); ok && t.Segments() {
		s.segmenter = t
		s.window = tcpLargeWindow
	}
	if options.Remote {
		s.window = tcpLargeWindow
	}
	for i := range s.identification {
		s.identification[i].Store(rand.Uint32())
	}
	if handler != nil {
		s.handle = handler.HandleConnection
		s.udp = newUdpConnectionHandler(s.handle, s.writeUDP)
	}
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
	sockets := s.sockets
	s.sockets = nil
	s.mu.Unlock()
	for _, c := range conns {
		c.mu.Lock()
		if c.err == nil {
			c.reset()
		}
		c.mu.Unlock()
	}
	for _, u := range sockets {
		u.queue.close()
	}
	return nil
}

// read takes the packets of the tun until it is closed
func (s *stack) read() {
	var err error
	if s.segmenter != nil {
		err = s.readSegments()
	} else {
		// as large as a packet can be, whatever the MTU is
		b := make([]byte, packetRoom+1<<16)
		for err == nil {
			var p []byte
			if p, err = s.tun.ReadPacket(b); err == nil {
				s.Input(p)
			}
		}
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if !closed {
		errors.LogErrorInner(s.ctx, err, "[tun] failed to read a packet, no more are read")
	}
}

// readSegments is read for a tun that does not split segments and gives them as large as a packet can be.
// They are read into buffers for a connection to keep what is large as it is, see keep
func (s *stack) readSegments() error {
	s.bufs = make(buf.MultiBuffer, (1<<16)/buf.Size)
	defer buf.ReleaseMulti(s.bufs)
	parts := make([][]byte, len(s.bufs))
	var r room
	for {
		for i, b := range s.bufs {
			if b == nil {
				s.bufs[i] = buf.New()
				_, _ = s.bufs[i].ReadFrom(&r)
				parts[i] = r.b
			}
		}
		n, err := s.segmenter.ReadParts(parts)
		if err != nil {
			return err
		}
		s.input(parts[0][:min(n, buf.Size)], max(n-buf.Size, 0))
	}
}

// room takes what it is given to read into as read: that is the room of a Buffer as it is, not cleared
type room struct{ b []byte }

func (r *room) Read(b []byte) (int, error) {
	r.b = b
	return len(b), nil
}

// Input implements Stack. Several tunnels may hand over their packets at once
func (s *stack) Input(b []byte) {
	s.input(b, 0)
}

// input takes a packet that is b and rest bytes after it, in the bufs that follow the one that b is in
func (s *stack) input(b []byte, rest int) {
	p, ok := parsePacket(b, rest)
	if !ok || p.src.Is4In6() || p.dst.Is4In6() || p.src.IsLoopback() || p.dst.IsLoopback() || p.dst.IsUnspecified() || p.src.IsMulticast() {
		// nothing comes from many at once, and an address that stands for this machine itself is not one
		// that the other side of a tun can ask for. Nor is an IPv6 address that stands for an IPv4 one, which
		// would be dialed as that: ::ffff:0.0.0.0 is this machine as well
		return
	}
	if s.verify && b[0]>>4 == 4 && checksum(sum(b[:int(b[0]&0xf)*4], 0)) != 0 {
		return
	}
	// what was put together may be of two packets with one number, its checksum tells
	verify := s.verify || p.fragment
	if p.rest != 0 && (verify || p.proto != protoTCP) {
		// only a segment of TCP that is not looked at can stay in pieces
		p.payload, p.rest = s.whole(p.payload, p.rest), 0
	}
	if p.fragment {
		p, ok = s.fragments.add(p)
	}
	if !ok || verify && !p.verified() {
		return
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

// whole returns in one piece what is b and rest bytes after it, in the bufs that follow the one that b is in
func (s *stack) whole(b []byte, rest int) []byte {
	if rest == 0 {
		return b
	}
	s.joined = append(s.joined[:0], b...)
	for i := 1; rest > 0; i++ {
		n := min(rest, buf.Size)
		s.joined = append(s.joined, s.bufs[i].BytesTo(int32(n))...)
		rest -= n
	}
	return s.joined
}

// keep adds to mb what is b and rest bytes after it, in the bufs that follow the one that b is in: nothing is copied,
// the buffers are taken for it and no longer read into
func (s *stack) keep(mb buf.MultiBuffer, b []byte, rest int) buf.MultiBuffer {
	// b ends where what was read into the first one does, or before it
	first := s.bufs[0]
	from := first.Cap() - int32(cap(b))
	first.Resize(from, from+int32(len(b)))
	mb, s.bufs[0] = append(mb, first), nil
	for i := 1; rest > 0; i++ {
		n := min(rest, buf.Size)
		s.bufs[i].Resize(0, int32(n))
		mb, s.bufs[i] = append(mb, s.bufs[i]), nil
		rest -= n
	}
	return mb
}

// local returns the address that packets to remote are sent from
func (s *stack) local(remote netip.Addr) (netip.Addr, error) {
	for _, a := range s.addresses {
		if a.Is4() == remote.Is4() {
			return a, nil
		}
	}
	return netip.Addr{}, errors.New("no address to reach ", remote, " from")
}

// ephemeral returns a port for what is opened from here: the first that free takes, from a random one on
func ephemeral(free func(port uint16) bool) (uint16, bool) {
	start := rand.Uint32()
	for i := range uint32(1 << 15) {
		if port := uint16(1<<15 | (start+i)&(1<<15-1)); free(port) {
			return port, true
		}
	}
	return 0, false
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
		rest:    p.rest,
	}

	s.mu.Lock()
	c := s.conns[f]
	s.mu.Unlock()
	if c != nil && c.input(seg) {
		return
	}
	if seg.flags&(tcpSyn|tcpAck|tcpRst) != tcpSyn || s.handle == nil {
		if seg.flags&tcpRst == 0 {
			s.refuse(f, seg)
		}
		return
	}

	if s.opening.Load() >= tcpOpening {
		return
	}
	c = newTCPConn(s, f)
	c.synchronize(seg)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.conns[f] = c
	s.mu.Unlock()
	s.opening.Add(1)
	c.mu.Lock()
	c.sendSyn()
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
		ack := seg.seq + uint32(len(seg.payload)+seg.rest)
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
	var socket *udpSocket
	if s.handle == nil {
		// only for a port that was opened from here
		s.mu.Lock()
		socket = s.sockets[netip.AddrPortFrom(p.dst, binary.BigEndian.Uint16(u[2:]))]
		s.mu.Unlock()
		if socket == nil {
			return
		}
	}
	// the packet waits for its reader, longer than read keeps it
	b := buf.NewWithSize(int32(size - udpHeaderSize))
	b.Write(u[udpHeaderSize:size])
	src := net.UDPDestination(net.IPAddress(p.src.AsSlice()), net.Port(binary.BigEndian.Uint16(u)))
	if socket == nil {
		s.udp.HandlePacket(src, net.UDPDestination(net.IPAddress(p.dst.AsSlice()), net.Port(binary.BigEndian.Uint16(u[2:]))), b)
	} else if b.UDP = &src; !socket.queue.push(b) {
		b.Release()
	}
}

// writeUDP writes a packet with the payload from src to dst to the tun
func (s *stack) writeUDP(payload []byte, src net.Destination, dst net.Destination) error {
	srcIP, _ := netip.AddrFromSlice(src.Address.IP())
	dstIP, _ := netip.AddrFromSlice(dst.Address.IP())
	return s.sendUDP(payload, netip.AddrPortFrom(srcIP, uint16(src.Port)), netip.AddrPortFrom(dstIP, uint16(dst.Port)))
}

func (s *stack) sendUDP(payload []byte, src, dst netip.AddrPort) error {
	srcIP, dstIP := src.Addr().Unmap(), dst.Addr().Unmap()
	if !srcIP.IsValid() || srcIP.Is4() != dstIP.Is4() || len(payload) > math.MaxUint16-udpHeaderSize {
		return errors.New("failed to write udp packet of ", len(payload), " bytes from ", src, " to ", dst)
	}
	var b [ipv6HeaderSize + udpHeaderSize]byte
	n := putIPHeader(b[:], protoUDP, srcIP, dstIP)
	u := b[n : n+udpHeaderSize]
	binary.BigEndian.PutUint16(u, src.Port())
	binary.BigEndian.PutUint16(u[2:], dst.Port())
	binary.BigEndian.PutUint16(u[4:], uint16(udpHeaderSize+len(payload)))
	check := transportChecksum(b[:n], protoUDP, u, payload)
	if check == 0 {
		// zero stands for no checksum
		check = 0xffff
	}
	binary.BigEndian.PutUint16(u[6:], check)
	return s.write(b[:n+udpHeaderSize], payload)
}

// write completes the IP header of a packet that is in two parts and writes it to the tun, in fragments if it is
// larger than the MTU. A segment of a connection never is, and is not written by this
func (s *stack) write(header, payload []byte) error {
	size, last := ipv6HeaderSize, 39
	if header[0]>>4 == 4 {
		size, last = ipv4HeaderSize, 19
	}
	// the group is chosen by the last bytes of the destination
	id := s.identification[(header[last]^header[last-1]<<3)%byte(len(s.identification))].Add(1)
	if header[0]>>4 == 4 {
		// a link on the way may split it as well, and what is put together there is told apart by its number
		binary.BigEndian.PutUint16(header[4:], uint16(id))
	}
	if len(header)+len(payload) > s.mtu {
		return writeFragments(s.tun, s.mtu, id, header, payload)
	}
	setIPLength(header[:size], len(header)+len(payload))
	return s.tun.WritePacket(header, payload)
}

// DialUDP implements Stack
func (s *stack) DialUDP() (net.PacketConn, error) {
	u := &udpSocket{stack: s, queue: newPacketQueue(udpQueueLimit)}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, io.ErrClosedPipe
	}
	port, ok := ephemeral(func(port uint16) bool {
		for _, a := range s.addresses {
			if s.sockets[netip.AddrPortFrom(a, port)] != nil {
				return false
			}
		}
		return true
	})
	if !ok || len(s.addresses) == 0 {
		return nil, errors.New("no port left on ", s.addresses)
	}
	u.port = port
	for _, a := range s.addresses {
		s.sockets[netip.AddrPortFrom(a, port)] = u
	}
	return u, nil
}

// udpSocket is a UDP port that was opened from here, on every address of the stack. It is not bound to one
// other side: what anyone sends to it is read from it, with who sent it
type udpSocket struct {
	stack *stack
	port  uint16
	queue *packetQueue
}

func (u *udpSocket) ReadFrom(p []byte) (int, net.Addr, error) {
	b, ok := u.queue.pop()
	if !ok {
		return 0, nil, gonet.ErrClosed
	}
	defer b.Release()
	return copy(p, b.Bytes()), b.UDP.RawNetAddr(), nil
}

func (u *udpSocket) WriteTo(p []byte, addr net.Addr) (int, error) {
	to, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("not a udp address: ", addr)
	}
	local, err := u.stack.local(to.AddrPort().Addr().Unmap())
	if err != nil {
		return 0, err
	}
	if err := u.stack.sendUDP(p, netip.AddrPortFrom(local, u.port), to.AddrPort()); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (u *udpSocket) Close() error {
	u.stack.mu.Lock()
	for _, a := range u.stack.addresses {
		if local := netip.AddrPortFrom(a, u.port); u.stack.sockets[local] == u {
			delete(u.stack.sockets, local)
		}
	}
	u.stack.mu.Unlock()
	u.queue.close()
	return nil
}

// LocalAddr implements net.PacketConn with the first address of the stack
func (u *udpSocket) LocalAddr() net.Addr {
	return gonet.UDPAddrFromAddrPort(netip.AddrPortFrom(u.stack.addresses[0], u.port))
}

func (u *udpSocket) SetDeadline(time.Time) error {
	return nil
}

func (u *udpSocket) SetReadDeadline(time.Time) error {
	return nil
}

func (u *udpSocket) SetWriteDeadline(time.Time) error {
	return nil
}

// handleICMP answers an echo request as its destination would, and takes the word that a packet of a connection
// was too large for a link on its way or found no way at all
func (s *stack) handleICMP(p packet) {
	m := p.payload
	request, reply := byte(8), byte(0)
	if p.proto == protoICMPv6 {
		request, reply = 128, 129
	}
	if len(m) < 8 {
		return
	}
	switch {
	case p.proto == protoICMPv4 && m[0] == 3 && m[1] == 4:
		s.undelivered(m[8:], max(int(binary.BigEndian.Uint16(m[6:])), ipv4SmallestMTU))
		return
	case p.proto == protoICMPv6 && m[0] == 2:
		s.undelivered(m[8:], max(int(binary.BigEndian.Uint32(m[4:])), ipv6SmallestMTU))
		return
	case p.proto == protoICMPv4 && m[0] == 3, p.proto == protoICMPv6 && m[0] == 1:
		s.undelivered(m[8:], 0)
		return
	}
	if m[0] != request || m[1] != 0 || s.handle == nil && !slices.Contains(s.addresses, p.dst) {
		// a stack that takes no connections is one host, not all of them
		return
	}
	var b [ipv6HeaderSize]byte
	n := putIPHeader(b[:], p.proto, p.dst, p.src)
	// the reply is the request with another type
	m[0], m[2], m[3] = reply, 0, 0
	if p.proto == protoICMPv6 {
		binary.BigEndian.PutUint16(m[2:], transportChecksum(b[:n], protoICMPv6, m, nil))
	} else {
		binary.BigEndian.PutUint16(m[2:], checksum(sum(m, 0)))
	}
	_ = s.write(b[:n], m)
}

// undelivered takes the start of a packet that was sent from here and did not get to where it goes. If it did not fit
// a link on its way, which takes packets of mtu bytes, the connection that sent it goes on with smaller segments.
// Without an mtu there is no way at all, and a connection that is being opened is not waited for
func (s *stack) undelivered(b []byte, mtu int) {
	var proto byte
	var local, remote netip.Addr
	switch {
	case len(b) >= ipv4HeaderSize && b[0]>>4 == 4:
		proto, local, remote = b[9], netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20]))
		b = b[min(int(b[0]&0xf)*4, len(b)):]
	case len(b) >= ipv6HeaderSize && b[0]>>4 == 6:
		proto, local, remote = b[6], netip.AddrFrom16([16]byte(b[8:24])), netip.AddrFrom16([16]byte(b[24:40]))
		b = b[ipv6HeaderSize:]
	}
	// of the segment there are the ports and the sequence number at least
	if proto != protoTCP || len(b) < 8 {
		return
	}
	s.mu.Lock()
	c := s.conns[flow{
		src: netip.AddrPortFrom(remote, binary.BigEndian.Uint16(b[2:])),
		dst: netip.AddrPortFrom(local, binary.BigEndian.Uint16(b)),
	}]
	s.mu.Unlock()
	if c == nil {
		return
	}
	if seq := binary.BigEndian.Uint32(b[4:]); mtu != 0 {
		c.shrink(seq, mtu)
	} else {
		c.unreachable(seq)
	}
}
