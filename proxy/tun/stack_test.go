package tun

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math"
	mrand "math/rand/v2"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

const testMTU = 1500

// link is a tun with the test on its other side
type link struct {
	// in is what the stack reads
	in chan []byte
	// out takes what the stack writes
	out func(packet []byte)
	// segments is set if the link takes segments that are larger than the MTU, wrong tells what was wrong with one
	segments bool
	wrong    func(args ...any)
	done     chan struct{}
	once     sync.Once
}

func newLink() *link {
	return &link{in: make(chan []byte, 512), done: make(chan struct{})}
}

func (l *link) Start() error          { return nil }
func (l *link) Name() (string, error) { return "test", nil }
func (l *link) Index() (int, error)   { return 1, nil }

func (l *link) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *link) ReadPacket(b []byte) ([]byte, error) {
	select {
	case packet := <-l.in:
		return b[packetRoom : packetRoom+copy(b[packetRoom:], packet)], nil
	case <-l.done:
		return nil, io.EOF
	}
}

func (l *link) WritePacket(header, payload []byte) error {
	l.out(append(append(make([]byte, 0, len(header)+len(payload)), header...), payload...))
	return nil
}

// Segments implements segmenter
func (l *link) Segments() bool {
	return l.segments
}

// WriteSegment implements segmenter as the system does when it sends a segment on: a packet for every mss bytes
func (l *link) WriteSegment(header []byte, payload [][]byte, mss int) error {
	data := bytes.Join(payload, nil)
	size := ipv4HeaderSize
	if header[0]>>4 == 6 {
		size = ipv6HeaderSize
	}
	if expected := ^checksum(pseudoSum(header[:size], protoTCP, len(header)-size+len(data))); binary.BigEndian.Uint16(header[size+16:]) != expected {
		l.wrong("checksum of a segment for the link to split: ", header[size+16:size+18], ", expected ", expected)
	}
	for sent := 0; sent < len(data); {
		n := min(mss, len(data)-sent)
		h := bytes.Clone(header)
		t := h[size:]
		binary.BigEndian.PutUint32(t[4:], binary.BigEndian.Uint32(t[4:])+uint32(sent))
		if sent+n < len(data) {
			t[13] &^= tcpFin | tcpPsh
		}
		t[16], t[17] = 0, 0
		setIPLength(h[:size], len(h)+n)
		binary.BigEndian.PutUint16(t[16:], transportChecksum(h[:size], protoTCP, t, data[sent:sent+n]))
		l.out(append(h, data[sent:sent+n]...))
		sent += n
	}
	return nil
}

func newTestStack(t *testing.T, l *link, handle func(net.Conn, net.Destination)) *stack {
	s := &stack{ctx: context.Background(), tun: l, mtu: testMTU, window: tcpWindow, handle: handle, conns: make(map[flow]*tcpConn), sockets: make(map[netip.AddrPort]*udpSocket)}
	if l.segments {
		s.segmenter, s.window, l.wrong = l, tcpLargeWindow, t.Error
	}
	if handle != nil {
		s.udp = newUdpConnectionHandler(handle, s.writeUDP)
	}
	s.Start()
	t.Cleanup(func() {
		s.Close()
		l.Close()
	})
	return s
}

// forgotten waits until the stack has no connection left
func forgotten(t *testing.T, s *stack) {
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		s.mu.Lock()
		n := len(s.conns)
		s.mu.Unlock()
		if n == 0 {
			if opening := s.opening.Load(); opening != 0 {
				t.Fatal("connections that are still counted as being opened: ", opening)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("connections left in the stack: ", n)
		}
	}
}

// echo sends back what it reads, and closes when the other side has
func echo(conn net.Conn, _ net.Destination) {
	defer conn.Close()
	for {
		mb, err := conn.(buf.Reader).ReadMultiBuffer()
		if err != nil {
			return
		}
		if conn.(buf.Writer).WriteMultiBuffer(mb) != nil {
			return
		}
	}
}

// peer is the system's end of one connection, with every segment made by the test
type peer struct {
	t        *testing.T
	l        *link
	sent     chan []byte
	src, dst netip.AddrPort
	// seq is the next that the peer sends, ack the next that it expects
	seq, ack uint32
	window   uint16
	// number is that of the last packet that the stack wrote in fragments
	number uint32
}

func newPeer(t *testing.T, src, dst string) (*peer, *link) {
	l := newLink()
	p := &peer{t: t, l: l, sent: make(chan []byte, 1024), src: netip.MustParseAddrPort(src), dst: netip.MustParseAddrPort(dst), seq: 1000, window: 0xffff}
	l.out = func(b []byte) { p.sent <- b }
	return p, l
}

// send gives the stack a segment of the peer
func (p *peer) send(seq uint32, flags byte, options, payload []byte) {
	p.l.in <- p.bytes(seq, flags, options, payload)
}

// bytes is the packet with a segment of the peer
func (p *peer) bytes(seq uint32, flags byte, options, payload []byte) []byte {
	var b [ipv6HeaderSize + tcpHeaderSize + 40]byte
	n := putIPHeader(b[:], protoTCP, p.src.Addr(), p.dst.Addr())
	t := b[n : n+tcpHeaderSize+len(options)]
	binary.BigEndian.PutUint16(t, p.src.Port())
	binary.BigEndian.PutUint16(t[2:], p.dst.Port())
	binary.BigEndian.PutUint32(t[4:], seq)
	binary.BigEndian.PutUint32(t[8:], p.ack)
	t[12] = byte(len(t)/4) << 4
	t[13] = flags
	binary.BigEndian.PutUint16(t[14:], p.window)
	copy(t[tcpHeaderSize:], options)
	setIPLength(b[:n], n+len(t)+len(payload))
	binary.BigEndian.PutUint16(t[16:], transportChecksum(b[:n], protoTCP, t, payload))
	return append(b[:n+len(t):n+len(t)], payload...)
}

// packet takes the next packet that the stack wrote
func (p *peer) packet() []byte {
	p.t.Helper()
	select {
	case b := <-p.sent:
		return b
	case <-time.After(5 * time.Second):
		p.t.Fatal("no packet from the stack")
		return nil
	}
}

// receive takes the next segment that the stack wrote and checks its addresses and checksums
func (p *peer) receive() segment {
	p.t.Helper()
	return p.segment(p.packet())
}

// dialed takes the SYN of a connection that the stack opens to the peer, which knows by it where that comes from.
// It returns the SYN and the packet that it came in
func (p *peer) dialed() (segment, []byte) {
	p.t.Helper()
	b := p.packet()
	packet, ok := parsePacket(b)
	if !ok || packet.proto != protoTCP || len(packet.payload) < tcpHeaderSize {
		p.t.Fatal("not a segment: ", b)
	}
	p.dst = netip.AddrPortFrom(packet.src, binary.BigEndian.Uint16(packet.payload))
	return p.segment(b), b
}

// segment reads the segment of a packet that the stack wrote and checks its addresses and checksums
func (p *peer) segment(b []byte) segment {
	p.t.Helper()
	size := ipv4HeaderSize
	if b[0]>>4 == 6 {
		size = ipv6HeaderSize
	} else if checksum(sum(b[:size], 0)) != 0 {
		p.t.Fatal("wrong checksum of the ip header")
	}
	packet, ok := parsePacket(b)
	if !ok || packet.proto != protoTCP || packet.src != p.dst.Addr() || packet.dst != p.src.Addr() {
		p.t.Fatal("not a segment of the connection: ", b)
	}
	t := packet.payload
	if transportChecksum(b[:size], protoTCP, t, nil) != 0 {
		p.t.Fatal("wrong checksum of the segment")
	}
	if binary.BigEndian.Uint16(t) != p.dst.Port() || binary.BigEndian.Uint16(t[2:]) != p.src.Port() {
		p.t.Fatal("wrong ports: ", t[:4])
	}
	offset := int(t[12]>>4) * 4
	return segment{
		seq:     binary.BigEndian.Uint32(t[4:]),
		ack:     binary.BigEndian.Uint32(t[8:]),
		flags:   t[13],
		window:  binary.BigEndian.Uint16(t[14:]),
		options: t[tcpHeaderSize:offset],
		payload: t[offset:],
	}
}

// icmp gives the stack an ICMP message from the peer, as it comes from a router on the way as well
func (p *peer) icmp(m []byte) {
	proto := byte(protoICMPv4)
	if p.src.Addr().Is6() {
		proto = protoICMPv6
	}
	var b [ipv6HeaderSize]byte
	n := putIPHeader(b[:], proto, p.src.Addr(), p.dst.Addr())
	setIPLength(b[:n], n+len(m))
	p.l.in <- append(b[:n:n], m...)
}

// tooLarge is the message that packet did not fit a link that takes mtu bytes
func tooLarge(packet []byte, mtu int) []byte {
	if packet[0]>>4 == 6 {
		return append([]byte{2, 0, 0, 0, 0, 0, byte(mtu >> 8), byte(mtu)}, packet[:ipv6HeaderSize+8]...)
	}
	// with the start of the packet, as far as the numbers of its segment
	return append([]byte{3, 4, 0, 0, 0, 0, byte(mtu >> 8), byte(mtu)}, packet[:int(packet[0]&0xf)*4+8]...)
}

// unreachable is the message that packet could not be delivered, for the reason that code stands for
func unreachable(packet []byte, code byte) []byte {
	if packet[0]>>4 == 6 {
		return append([]byte{1, code, 0, 0, 0, 0, 0, 0}, packet[:ipv6HeaderSize+8]...)
	}
	return append([]byte{3, code, 0, 0, 0, 0, 0, 0}, packet[:ipv4HeaderSize+8]...)
}

// ping is an echo request without a checksum
func ping(src, dst netip.Addr) []byte {
	proto, request := byte(protoICMPv4), byte(8)
	if src.Is6() {
		proto, request = protoICMPv6, 128
	}
	var ip [ipv6HeaderSize]byte
	n := putIPHeader(ip[:], proto, src, dst)
	setIPLength(ip[:n], n+8)
	return append(ip[:n:n], request, 0, 0, 0, 1, 2, 3, 4)
}

// udpPacket is a UDP packet without a checksum
func udpPacket(src, dst netip.AddrPort, payload []byte) []byte {
	var b [ipv6HeaderSize + udpHeaderSize]byte
	n := putIPHeader(b[:], protoUDP, src.Addr(), dst.Addr())
	u := b[n : n+udpHeaderSize]
	binary.BigEndian.PutUint16(u, src.Port())
	binary.BigEndian.PutUint16(u[2:], dst.Port())
	binary.BigEndian.PutUint16(u[4:], uint16(udpHeaderSize+len(payload)))
	setIPLength(b[:n], n+udpHeaderSize+len(payload))
	return append(b[:n+udpHeaderSize:n+udpHeaderSize], payload...)
}

// udp gives the stack a UDP packet
func (p *peer) udp(src, dst netip.AddrPort, payload string) {
	p.l.in <- udpPacket(src, dst, []byte(payload))
}

// silent fails if the stack writes something within d
func (p *peer) silent(d time.Duration) {
	p.t.Helper()
	select {
	case b := <-p.sent:
		p.t.Fatal("unexpected packet from the stack: ", b)
	case <-time.After(d):
	}
}

// connect opens the connection with the given options in the SYN and returns the options of the answer
func (p *peer) connect(options []byte) []byte {
	p.t.Helper()
	p.send(p.seq, tcpSyn, options, nil)
	p.seq++
	s := p.receive()
	if s.flags != tcpSyn|tcpAck || s.ack != p.seq {
		p.t.Fatal("not an answer to the SYN: flags ", s.flags, ", ack ", s.ack)
	}
	p.ack = s.seq + 1
	p.send(p.seq, tcpAck, nil, nil)
	return s.options
}

// accepted is what a test gets of the connections that the stack hands over
type accepted struct {
	conn net.Conn
	dest net.Destination
}

func accept(conns chan accepted) func(net.Conn, net.Destination) {
	return func(conn net.Conn, dest net.Destination) { conns <- accepted{conn, dest} }
}

func take(t *testing.T, conns chan accepted) accepted {
	t.Helper()
	select {
	case a := <-conns:
		return a
	case <-time.After(5 * time.Second):
		t.Fatal("no connection from the stack")
		return accepted{}
	}
}

func write(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	if err := conn.(buf.Writer).WriteMultiBuffer(buf.MergeBytes(nil, payload)); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, conn net.Conn, expected string) {
	t.Helper()
	mb, err := conn.(buf.Reader).ReadMultiBuffer()
	if err != nil || mb.String() != expected {
		t.Fatal("read ", mb.String(), ", expected ", expected, ", error: ", err)
	}
	buf.ReleaseMulti(mb)
}

// The options of the SYN decide what the answer has, and both ends close the connection in turn.
func TestTCPHandshakeAndClose(t *testing.T) {
	for _, test := range []struct {
		src, dst          string
		options, expected []byte
	}{
		{"10.0.0.1:1234", "10.0.0.2:80", nil, []byte{2, 4, 5, 0xb4}},
		{"10.0.0.1:1234", "10.0.0.2:80", []byte{2, 4, 2, 0, 4, 2, 1, 3, 3, 7, 0, 0}, []byte{2, 4, 5, 0xb4, 1, 1, 4, 2, 1, 3, 3, tcpWindowShift}},
		{"[fd00::1]:1234", "[fd00::2]:80", []byte{2, 4, 5, 0xa0, 1, 3, 3, 7}, []byte{2, 4, 5, 0xa0, 1, 3, 3, tcpWindowShift}},
		// the times of RFC 7323 are for a stack of a tunnel
		{"10.0.0.1:1234", "10.0.0.2:80", []byte{2, 4, 5, 0xb4, 1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0}, []byte{2, 4, 5, 0xb4}},
	} {
		conns := make(chan accepted, 1)
		p, l := newPeer(t, test.src, test.dst)
		s := newTestStack(t, l, accept(conns))
		if options := p.connect(test.options); !bytes.Equal(options, test.expected) {
			t.Fatal("options ", options, ", expected ", test.expected)
		}
		a := take(t, conns)
		if a.dest != net.TCPDestination(net.ParseAddress(p.dst.Addr().String()), net.Port(80)) || a.conn.RemoteAddr().String() != test.src {
			t.Fatal("connection from ", a.conn.RemoteAddr(), " to ", a.dest)
		}

		// the system closes its side, what it sent is read first
		p.send(p.seq, tcpAck|tcpPsh|tcpFin, nil, []byte("abc"))
		p.seq += 4
		if s := p.receive(); s.flags != tcpAck || s.ack != p.seq {
			t.Fatal("the FIN is not acknowledged: flags ", s.flags, ", ack ", s.ack)
		}
		read(t, a.conn, "abc")
		if _, err := a.conn.(buf.Reader).ReadMultiBuffer(); err != io.EOF {
			t.Fatal("no end of the stream: ", err)
		}
		// the other side is still open
		write(t, a.conn, []byte("def"))
		if s := p.receive(); string(s.payload) != "def" || s.seq != p.ack || s.flags != tcpAck|tcpPsh {
			t.Fatal("wrong segment: seq ", s.seq, ", flags ", s.flags, ", payload ", s.payload)
		}
		p.ack += 3
		a.conn.Close()
		if s := p.receive(); s.flags != tcpFin|tcpAck || s.seq != p.ack {
			t.Fatal("not a FIN: flags ", s.flags, ", seq ", s.seq)
		}
		p.ack++
		// what the system sends again is not something that nobody reads anymore
		p.send(p.seq-4, tcpAck|tcpPsh|tcpFin, nil, []byte("abc"))
		if s := p.receive(); s.flags != tcpAck || s.ack != p.seq {
			t.Fatal("what was sent again is not acknowledged: flags ", s.flags, ", ack ", s.ack)
		}
		p.send(p.seq, tcpAck, nil, nil)
		forgotten(t, s)
		// what comes for it now is refused
		p.send(p.seq, tcpAck, nil, nil)
		if s := p.receive(); s.flags != tcpRst || s.seq != p.ack {
			t.Fatal("not a reset: flags ", s.flags, ", seq ", s.seq)
		}
	}
}

// What comes after a lost segment is kept and told to the system, and is read once the lost one comes.
func TestTCPOutOfOrder(t *testing.T) {
	conns := make(chan accepted, 1)
	p, l := newPeer(t, "10.0.0.1:1234", "10.0.0.2:80")
	newTestStack(t, l, accept(conns))
	p.connect([]byte{2, 4, 5, 0xb4, 4, 2, 0, 0})
	a := take(t, conns)

	sack := func(s segment, blocks ...uint32) {
		t.Helper()
		expected := []byte{1, 1, 5, byte(2 + 4*len(blocks))}
		for _, edge := range blocks {
			expected = binary.BigEndian.AppendUint32(expected, edge)
		}
		if s.flags != tcpAck || s.ack != p.seq || !bytes.Equal(s.options, expected) {
			t.Fatal("ack ", s.ack, " with options ", s.options, ", expected ", p.seq, " with ", expected)
		}
	}
	// "abc" is lost, then "ghi" and "def" come, each told with the block that it is in first
	p.send(p.seq+6, tcpAck, nil, []byte("ghi"))
	sack(p.receive(), p.seq+6, p.seq+9)
	p.send(p.seq+12, tcpAck, nil, []byte("mno"))
	sack(p.receive(), p.seq+12, p.seq+15, p.seq+6, p.seq+9)
	p.send(p.seq+3, tcpAck, nil, []byte("def"))
	sack(p.receive(), p.seq+3, p.seq+9, p.seq+12, p.seq+15)
	// the same again changes nothing
	p.send(p.seq+3, tcpAck, nil, []byte("defg"))
	sack(p.receive(), p.seq+3, p.seq+9, p.seq+12, p.seq+15)

	p.send(p.seq, tcpAck, nil, []byte("abc"))
	p.seq += 9
	sack(p.receive(), p.seq+3, p.seq+6)
	read(t, a.conn, "abcdefghi")
	p.send(p.seq, tcpAck, nil, []byte("jklm"))
	p.seq += 6
	if s := p.receive(); s.ack != p.seq || len(s.options) != 0 {
		t.Fatal("ack ", s.ack, " with options ", s.options)
	}
	read(t, a.conn, "jklmno")
}

// A segment is as large as the system makes it when the tun does not split what it reads.
func TestTCPLargeSegment(t *testing.T) {
	conns := make(chan accepted, 1)
	p, l := newPeer(t, "10.0.0.1:1234", "10.0.0.2:80")
	newTestStack(t, l, accept(conns))
	p.connect(nil)
	a := take(t, conns)

	sent := make([]byte, 60000)
	rand.Read(sent)
	p.send(p.seq, tcpAck|tcpPsh, nil, sent)
	var received []byte
	for len(received) < len(sent) {
		mb, err := a.conn.(buf.Reader).ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range mb {
			received = append(received, b.Bytes()...)
		}
		buf.ReleaseMulti(mb)
	}
	if !bytes.Equal(received, sent) {
		t.Fatal("read something else than what was sent")
	}
}

// What the system does not acknowledge is sent again: at once when it says what it has past it, or after a while.
func TestTCPRetransmit(t *testing.T) {
	conns := make(chan accepted, 1)
	p, l := newPeer(t, "10.0.0.1:1234", "10.0.0.2:80")
	newTestStack(t, l, accept(conns))
	p.connect([]byte{2, 4, 0, 100, 4, 2, 0, 0})
	a := take(t, conns)

	sent := make([]byte, 450)
	rand.Read(sent)
	go func() {
		if err := a.conn.(buf.Writer).WriteMultiBuffer(buf.MergeBytes(nil, sent)); err != nil {
			t.Error(err)
		}
	}()
	for i := 0; i < 5; i++ {
		limit := 100
		if i == 4 {
			limit = 50
		}
		if s := p.receive(); s.seq != p.ack+uint32(100*i) || !bytes.Equal(s.payload, sent[100*i:100*i+limit]) {
			t.Fatal("segment ", i, ": seq ", s.seq-p.ack, " with ", len(s.payload), " bytes")
		}
	}
	// the second and the third segment are lost
	p.ack += 100
	p.send(p.seq, tcpAck, nil, nil)
	block := func(from, to uint32) []byte {
		b := []byte{1, 1, 5, 10}
		return binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(b, from), to)
	}
	p.send(p.seq, tcpAck, block(p.ack+200, p.ack+350), nil)
	for i := 1; i < 3; i++ {
		if s := p.receive(); s.seq != p.ack+uint32(100*(i-1)) || !bytes.Equal(s.payload, sent[100*i:100*i+100]) {
			t.Fatal("segment ", i, " sent again: seq ", s.seq-p.ack, " with ", len(s.payload), " bytes")
		}
	}
	// said again, it is not sent again
	p.send(p.seq, tcpAck, block(p.ack+200, p.ack+350), nil)
	p.silent(tcpTick)
	// the one that was sent again came, the other one did not: it is sent after a while, without what the system has
	p.ack += 100
	p.send(p.seq, tcpAck, block(p.ack+100, p.ack+250), nil)
	p.silent(tcpTick)
	if s := p.receive(); s.seq != p.ack || !bytes.Equal(s.payload, sent[200:300]) {
		t.Fatal("segment 2 sent again later: seq ", s.seq-p.ack, " with ", len(s.payload), " bytes")
	}
	p.ack += 250
	p.send(p.seq, tcpAck, nil, nil)
	p.silent(2 * tcpRetransmitTicks * tcpTick)
}

// No more is sent at once than has arrived before: twice as much when all of it arrives, half of it after a loss.
func TestTCPCongestion(t *testing.T) {
	conns := make(chan accepted, 1)
	p, l := newPeer(t, "10.0.0.1:1234", "10.0.0.2:80")
	newTestStack(t, l, accept(conns))
	p.connect([]byte{2, 4, 0, 100, 4, 2, 0, 0})
	a := take(t, conns)

	go a.conn.(buf.Writer).WriteMultiBuffer(buf.MergeBytes(nil, make([]byte, 8000)))
	// next is where what is new starts
	next := p.ack
	segments := func(seqs ...uint32) {
		t.Helper()
		for _, seq := range seqs {
			if s := p.receive(); s.seq != seq || len(s.payload) != 100 {
				t.Fatal("seq ", s.seq-p.ack, " with ", len(s.payload), " bytes, expected ", seq-p.ack, " with 100")
			}
		}
		p.silent(tcpTick / 2)
	}
	fresh := func(n int) (seqs []uint32) {
		for ; n > 0; n-- {
			seqs = append(seqs, next)
			next += 100
		}
		return
	}
	segments(fresh(tcpStart)...)
	p.ack = next
	p.send(p.seq, tcpAck, nil, nil)
	segments(fresh(2 * tcpStart)...)
	// the first of them is lost: it is sent again, and with what is new there is half as much on its way as before
	p.send(p.seq, tcpAck, binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32([]byte{1, 1, 5, 10}, p.ack+100), next), nil)
	segments(append([]uint32{p.ack}, fresh(tcpStart-1)...)...)
	// from then on a segment more for as much as there was on its way, and never a part of one
	p.ack = next
	p.send(p.seq, tcpAck, nil, nil)
	segments(fresh(tcpStart + 2)...)
}

// A loss is paid for once. Acknowledgments that repeat themselves tell of one only when the system cannot say what
// it has. A segment that was sent again is sent once more when the system still asks for it after an answer had the
// time to come, and the timer waits for that one. When the timer runs out all the same, the way takes no less
// afterwards than after the loss, and it is not given at once what one acknowledgment then says has arrived.
func TestTCPLossAgain(t *testing.T) {
	conns := make(chan accepted, 5)
	// start opens a connection that says what it has if sack is set, with twenty segments sent and not acknowledged
	start := func(src string, sack bool) (*peer, *tcpConn) {
		t.Helper()
		p, l := newPeer(t, src, "10.0.0.2:80")
		newTestStack(t, l, accept(conns))
		options := []byte{2, 4, 0, 100}
		if sack {
			options = append(options, 4, 2, 0, 0)
		}
		p.connect(options)
		a := take(t, conns)
		go a.conn.(buf.Writer).WriteMultiBuffer(buf.MergeBytes(nil, make([]byte, 8000)))
		for range tcpStart {
			p.receive()
		}
		p.ack += 100 * tcpStart
		p.send(p.seq, tcpAck, nil, nil)
		for range 2 * tcpStart {
			p.receive()
		}
		return p, a.conn.(*tcpConn)
	}
	// has says that the system has what it was sent from from to to, past what it acknowledges
	has := func(p *peer, from, to uint32) []byte {
		return binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32([]byte{1, 1, 5, 10}, p.ack+from), p.ack+to)
	}
	again := func(p *peer, what string) {
		t.Helper()
		if s := p.receive(); s.seq != p.ack || len(s.payload) != 100 {
			t.Fatal(what, ": seq ", s.seq-p.ack, " with ", len(s.payload), " bytes")
		}
	}

	p, c := start("10.0.0.1:1234", true)
	state := func() (cwnd, ssthresh uint32, stalled, retransmits int) {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.cwnd, c.ssthresh, c.stalled, c.retransmits
	}
	// the system repeats itself, as it does for a segment that it got twice: it would say what it has if one were lost
	for range 3 {
		p.send(p.seq, tcpAck, nil, nil)
	}
	p.silent(tcpTick / 2)
	if cwnd, _, _, _ := state(); cwnd != 2*tcpStart*100 {
		t.Fatal("the way takes ", cwnd, " after acknowledgments that repeat themselves")
	}

	// an answer takes a while, and so does the system before it says that the first of them is missing
	c.mu.Lock()
	c.srtt, c.rttvar = tcpTick, 0
	c.mu.Unlock()
	time.Sleep(tcpTick - tcpTick/5)
	p.send(p.seq, tcpAck, has(p, 100, 2000), nil)
	again(p, "the lost one")
	// the timer waits for the answer from when that was sent again, and half as much is on its way as before
	if _, ssthresh, stalled, _ := state(); ssthresh != tcpStart*100 || stalled != 0 {
		t.Fatal("after a loss the way takes ", ssthresh, ", the timer has waited ", stalled, " ticks")
	}
	for range tcpStart - 1 {
		p.receive()
	}
	// it says so again before the answer to what was sent again could be there: nothing
	time.Sleep(tcpTick / 2)
	p.send(p.seq, tcpAck, has(p, 100, 2000), nil)
	p.silent(tcpTick)
	// and again after that time: what was sent again is lost as well, and is sent once more
	p.send(p.seq, tcpAck, has(p, 100, 2000), nil)
	again(p, "the lost one once more")
	if _, _, stalled, retransmits := state(); stalled != 0 || retransmits != 0 {
		t.Fatal("sent once more by the timer ", retransmits, " times, which has waited ", stalled, " ticks")
	}
	// that was the one time. The timer waits for the answer to it, then it runs out: the way is tried with one
	// segment, and takes no less afterwards than after the loss
	time.Sleep(tcpTick + tcpTick/3)
	p.send(p.seq, tcpAck, has(p, 100, 2000), nil)
	p.silent(tcpTick / 4)
	again(p, "the lost one after the timer")
	if cwnd, ssthresh, _, retransmits := state(); cwnd != 100 || ssthresh != tcpStart*100 || retransmits != 1 {
		t.Fatal("after the timer the way takes ", cwnd, " and then ", ssthresh, ", sent again ", retransmits, " times")
	}
	// all of it arrives with the one that was sent again: that is not how much the way takes at once
	p.ack += 100 * (3*tcpStart - 1)
	p.send(p.seq, tcpAck, nil, nil)
	for range 3 {
		p.receive()
	}
	p.silent(tcpTick / 2)
	if cwnd, _, _, _ := state(); cwnd != 300 {
		t.Fatal("the way takes ", cwnd, " after one acknowledgment for all that was lost")
	}
	// the next loss on the connection: its first segment is sent again once, whatever time the last loss has left
	time.Sleep(tcpTick)
	p.send(p.seq, tcpAck, has(p, 100, 300), nil)
	again(p, "the first of the next loss")
	if s := p.receive(); s.seq == p.ack {
		t.Fatal("the first of the next loss is sent again twice")
	}
	p.silent(tcpTick / 2)

	// two are lost. When the first has come, the second is waited for as long as an answer takes
	p, c = start("10.0.0.1:1235", true)
	c.mu.Lock()
	c.srtt, c.rttvar = tcpTick, 0
	c.mu.Unlock()
	p.send(p.seq, tcpAck, has(p, 200, 2000), nil)
	again(p, "the first of two")
	if s := p.receive(); s.seq != p.ack+100 {
		t.Fatal("not the second of two: seq ", s.seq-p.ack)
	}
	for range tcpStart - 2 {
		p.receive()
	}
	time.Sleep(tcpTick + tcpTick/2)
	p.ack += 100
	p.send(p.seq, tcpAck, has(p, 100, 1900), nil)
	if s := p.receive(); s.seq == p.ack {
		t.Fatal("the second of two is sent again with the answer to the first")
	}
	p.send(p.seq, tcpAck, has(p, 100, 1900), nil)
	p.silent(tcpTick / 2)

	// an answer that takes next to no time is given some all the same: the stack may get to what the system said
	// before only after it
	p, c = start("10.0.0.1:1237", true)
	c.mu.Lock()
	c.srtt, c.rttvar = time.Millisecond, 0
	c.mu.Unlock()
	p.send(p.seq, tcpAck, has(p, 100, 2000), nil)
	again(p, "the lost one of a near system")
	for range tcpStart - 1 {
		p.receive()
	}
	time.Sleep(tcpTick / 20)
	p.send(p.seq, tcpAck, has(p, 100, 2000), nil)
	p.silent(tcpTick / 20)
	time.Sleep(tcpTick / 4)
	p.send(p.seq, tcpAck, has(p, 100, 2000), nil)
	again(p, "the lost one of a near system once more")
	if _, _, _, retransmits := state(); retransmits != 0 {
		t.Fatal("sent once more by the timer")
	}

	// a timer that runs out with no loss seen before does halve what the way takes
	p, c = start("10.0.0.1:1238", true)
	again(p, "the first segment after the timer")
	if cwnd, ssthresh, _, retransmits := state(); cwnd != 100 || ssthresh != tcpStart*100 || retransmits != 1 {
		t.Fatal("after the timer the way takes ", cwnd, " and then ", ssthresh, ", sent again ", retransmits, " times")
	}

	// a system that cannot say what it has: the third time it says the same, the segment is lost
	p, c = start("10.0.0.1:1236", false)
	for range 2 {
		p.send(p.seq, tcpAck, nil, nil)
	}
	p.silent(tcpTick / 2)
	p.send(p.seq, tcpAck, nil, nil)
	again(p, "the first segment")
	if _, _, _, retransmits := state(); retransmits != 0 {
		t.Fatal("sent again by the timer")
	}
}

// while the way to the system is away an open connection sends again every two seconds at most, so that it goes on
// soon after the way is back, while the next segment still waits the doubled time, and it is given up when nothing
// was acknowledged for long enough
func TestTCPWayBack(t *testing.T) {
	conns := make(chan accepted, 1)
	p, l := newPeer(t, "10.0.0.1:1234", "10.0.0.2:80")
	s := newTestStack(t, l, accept(conns))
	p.connect([]byte{2, 4, 0, 100})
	a := take(t, conns)
	c := a.conn.(*tcpConn)

	// an answer takes a while: the timer waits as long once, and then no longer than two seconds
	c.mu.Lock()
	c.retransmitTicks = tcpRetransmitTicksOpen * 4 / 5
	c.mu.Unlock()
	start := time.Now()
	go a.conn.(buf.Writer).WriteMultiBuffer(buf.MergeBytes(nil, make([]byte, 100)))
	p.receive()
	for i, most := range []time.Duration{tcpRetransmitTicksOpen * 4 / 5 * tcpTick, tcpRetransmitTicksOpen * tcpTick} {
		if s := p.receive(); s.seq != p.ack || len(s.payload) != 100 {
			t.Fatal("not sent again: seq ", s.seq-p.ack, " with ", len(s.payload), " bytes")
		}
		if d := time.Since(start); d > most+most/4 || d < most-2*tcpTick {
			t.Fatal("sent again ", i+1, " after ", d, ", not after ", most)
		}
		start = time.Now()
	}
	c.mu.Lock()
	ticks := c.retransmitTicks
	c.mu.Unlock()
	if ticks != tcpRetransmitTicksOpen*4/5*4 {
		t.Fatal("the next segment waits ", ticks, " ticks")
	}

	// the way is back
	p.ack += 100
	p.send(p.seq, tcpAck, nil, nil)
	p.silent(tcpTick)
	c.mu.Lock()
	retransmits := c.retransmits
	c.mu.Unlock()
	if retransmits != 0 {
		t.Fatal("sent again ", retransmits, " times after the acknowledgment")
	}

	// it is away again, now for longer than the connection waits
	c.mu.Lock()
	c.retransmitTicks = tcpRetransmitTicks
	c.mu.Unlock()
	go a.conn.(buf.Writer).WriteMultiBuffer(buf.MergeBytes(nil, make([]byte, 100)))
	p.receive()
	p.receive()
	c.mu.Lock()
	c.lostTicks = tcpGiveUpTicks
	c.mu.Unlock()
	result := make(chan error, 1)
	go func() {
		_, err := a.conn.Read(make([]byte, 1))
		result <- err
	}()
	select {
	case err := <-result:
		if err != errTCPTimeout {
			t.Fatal("not given up: ", err)
		}
	case <-time.After(2*tcpRetransmitTicksOpen*tcpTick + time.Second):
		t.Fatal("not given up")
	}
	forgotten(t, s)
}

// No more is sent than the system takes, and the writer goes on when it takes more.
// The FIN that comes with a segment before the one in front of it is taken when that one has come.
func TestTCPEndOutOfOrder(t *testing.T) {
	conns := make(chan accepted, 1)
	p, l := newPeer(t, "10.0.0.1:1234", "10.0.0.2:80")
	newTestStack(t, l, accept(conns))
	p.connect(nil)
	a := take(t, conns)
	p.send(p.seq+3, tcpAck|tcpFin, nil, []byte("def"))
	if s := p.receive(); s.ack != p.seq {
		t.Fatal("ack ", s.ack, ", expected ", p.seq)
	}
	p.send(p.seq, tcpAck, nil, []byte("abc"))
	p.seq += 7
	if s := p.receive(); s.ack != p.seq {
		t.Fatal("ack ", s.ack, ", expected ", p.seq, " with the end")
	}
	read(t, a.conn, "abcdef")
	if _, err := a.conn.(buf.Reader).ReadMultiBuffer(); err != io.EOF {
		t.Fatal("no end after what was read: ", err)
	}
}

// The answer to the SYN-ACK tells how far the system is, and a segment is not sent again before
// its acknowledgment had the time to come from there.
func TestTCPRoundTrip(t *testing.T) {
	conns := make(chan accepted, 1)
	p, l := newPeer(t, "10.0.0.1:1234", "10.0.0.2:80")
	newTestStack(t, l, accept(conns))
	p.send(p.seq, tcpSyn, nil, nil)
	p.seq++
	p.ack = p.receive().seq + 1
	time.Sleep(150 * time.Millisecond)
	p.send(p.seq, tcpAck, nil, nil)
	a := take(t, conns)
	write(t, a.conn, []byte("abc"))
	for range 2 {
		if s := p.receive(); s.seq != p.ack || string(s.payload) != "abc" {
			t.Fatal("seq ", s.seq, " with ", s.payload)
		}
		p.silent(350 * time.Millisecond)
	}
}

// A peer that says its segments are tiny is not believed all the way.
func TestTCPSmallestSegment(t *testing.T) {
	conns := make(chan accepted, 1)
	p, l := newPeer(t, "10.0.0.1:1234", "10.0.0.2:80")
	newTestStack(t, l, accept(conns))
	p.connect([]byte{2, 4, 0, 1})
	a := take(t, conns)
	write(t, a.conn, make([]byte, 100))
	if s := p.receive(); len(s.payload) != tcpSmallest {
		t.Fatal("a segment of ", len(s.payload), " bytes")
	}
}

func TestTCPWindow(t *testing.T) {
	conns := make(chan accepted, 1)
	p, l := newPeer(t, "10.0.0.1:1234", "10.0.0.2:80")
	newTestStack(t, l, accept(conns))
	p.window = 250
	p.connect(nil)
	a := take(t, conns)

	sent := make([]byte, 1000)
	rand.Read(sent)
	done := make(chan struct{})
	go func() {
		if err := a.conn.(buf.Writer).WriteMultiBuffer(buf.MergeBytes(nil, sent)); err != nil {
			t.Error(err)
		}
		close(done)
	}()
	var received []byte
	for len(received) < len(sent) {
		for space := 250; space > 0; {
			s := p.receive()
			if s.seq != p.ack || len(s.payload) > space {
				t.Fatal("seq ", s.seq, " with ", len(s.payload), " bytes, expected ", p.ack, " with ", space, " at most")
			}
			received = append(received, s.payload...)
			p.ack += uint32(len(s.payload))
			space -= len(s.payload)
		}
		// nothing more before the window opens
		p.silent(tcpTick / 2)
		p.send(p.seq, tcpAck, nil, nil)
	}
	<-done
	if !bytes.Equal(received, sent) {
		t.Fatal("received something else than what was written")
	}

	// the time that the window was closed is not time without an acknowledgment of what is sent after it.
	// It is closed with a keepalive: that is answered, so the stack has seen it before something is written
	p.window = 0
	p.send(p.seq-1, tcpAck, nil, nil)
	p.receive()
	done = make(chan struct{})
	go func() {
		if err := a.conn.(buf.Writer).WriteMultiBuffer(buf.MergeBytes(nil, []byte("abc"))); err != nil {
			t.Error(err)
		}
		close(done)
	}()
	p.silent(4 * tcpTick)
	p.window = 250
	p.send(p.seq, tcpAck, nil, nil)
	if s := p.receive(); s.seq != p.ack || string(s.payload) != "abc" {
		t.Fatal("seq ", s.seq, " with ", s.payload)
	}
	<-done
	p.silent(tcpTick + tcpTick/2)
}

// A keepalive is answered, and not before a segment that was made before it is written.
func TestTCPKeepalive(t *testing.T) {
	conns := make(chan accepted, 1)
	p, l := newPeer(t, "10.0.0.1:1234", "10.0.0.2:80")
	// the write of the segment with what is written below takes until it is let go
	out, writing, written := l.out, make(chan struct{}), make(chan struct{})
	l.out = func(b []byte) {
		if b[ipv4HeaderSize+13]&tcpPsh != 0 {
			close(writing)
			<-written
		}
		out(b)
	}
	newTestStack(t, l, accept(conns))
	p.connect(nil)
	a := take(t, conns)

	p.send(p.seq-1, tcpAck, nil, nil)
	if s := p.receive(); s.flags != tcpAck || s.seq != p.ack || s.ack != p.seq {
		t.Fatal("not an answer to the keepalive: flags ", s.flags, ", seq ", s.seq, ", ack ", s.ack)
	}

	go func() {
		if err := a.conn.(buf.Writer).WriteMultiBuffer(buf.MergeBytes(nil, []byte("abc"))); err != nil {
			t.Error(err)
		}
	}()
	<-writing
	p.send(p.seq-1, tcpAck, nil, nil)
	p.silent(tcpTick / 2)
	close(written)
	if s := p.receive(); string(s.payload) != "abc" || s.seq != p.ack {
		t.Fatal("wrong segment: seq ", s.seq, ", flags ", s.flags, ", payload ", s.payload)
	}
	p.ack += 3
	if s := p.receive(); s.flags != tcpAck || s.seq != p.ack || s.ack != p.seq || len(s.payload) != 0 {
		t.Fatal("not an answer to the keepalive: flags ", s.flags, ", seq ", s.seq, ", ack ", s.ack)
	}
	p.send(p.seq, tcpAck, nil, nil)
}

// A reset ends the connection for its reader, and a connection that is closed with something unread is reset.
func TestTCPReset(t *testing.T) {
	conns := make(chan accepted, 1)
	p, l := newPeer(t, "10.0.0.1:1234", "10.0.0.2:80")
	s := newTestStack(t, l, accept(conns))
	p.connect(nil)
	a := take(t, conns)
	// a reset from somewhere else than where the connection is changes nothing
	p.send(p.seq+tcpWindow+1, tcpRst, nil, nil)
	p.send(p.seq-1, tcpRst, nil, nil)
	p.send(p.seq, tcpAck|tcpPsh, nil, []byte("abc"))
	p.seq += 3
	read(t, a.conn, "abc")
	if s := p.receive(); s.flags != tcpAck || s.ack != p.seq {
		t.Fatal("not acknowledged: flags ", s.flags, ", ack ", s.ack)
	}
	p.send(p.seq, tcpRst, nil, nil)
	if _, err := a.conn.(buf.Reader).ReadMultiBuffer(); err == nil || err == io.EOF {
		t.Fatal("no error after the reset: ", err)
	}
	a.conn.Close()
	forgotten(t, s)

	// what came before the reset is read, to its end
	p.src = netip.MustParseAddrPort("10.0.0.1:1236")
	p.connect(nil)
	a = take(t, conns)
	p.send(p.seq, tcpAck|tcpPsh|tcpFin, nil, []byte("abc"))
	p.seq += 4
	if s := p.receive(); s.flags != tcpAck || s.ack != p.seq {
		t.Fatal("not acknowledged: flags ", s.flags, ", ack ", s.ack)
	}
	// with the number of the FIN, as the answer to a segment that was made before the FIN came
	p.send(p.seq-1, tcpRst, nil, nil)
	forgotten(t, s)
	read(t, a.conn, "abc")
	if _, err := a.conn.(buf.Reader).ReadMultiBuffer(); err != io.EOF {
		t.Fatal("no end after what was read: ", err)
	}
	a.conn.Close()

	p.src = netip.MustParseAddrPort("10.0.0.1:1235")
	p.connect(nil)
	a = take(t, conns)
	p.send(p.seq, tcpAck|tcpPsh, nil, []byte("abc"))
	p.seq += 3
	// the timer acknowledges what nobody reads
	if s := p.receive(); s.flags != tcpAck || s.ack != p.seq {
		t.Fatal("not acknowledged: flags ", s.flags, ", ack ", s.ack)
	}
	a.conn.Close()
	if s := p.receive(); s.flags != tcpRst|tcpAck || s.seq != p.ack {
		t.Fatal("not a reset: flags ", s.flags, ", seq ", s.seq)
	}
	forgotten(t, s)

	// one that the system gives up before it is open is not one that is being opened anymore
	p.src = netip.MustParseAddrPort("10.0.0.1:1237")
	p.send(p.seq, tcpSyn, nil, nil)
	p.seq++
	p.receive()
	p.send(p.seq, tcpRst, nil, nil)
	forgotten(t, s)
}

// A SYN on a connection that is closed opens it anew when it comes from the system of this machine, which has let the
// old one go. Through a tunnel it is answered with what is expected, as anyone who knows the addresses could send it.
func TestTCPSynAfterClose(t *testing.T) {
	for _, tunnel := range []bool{false, true} {
		conns := make(chan accepted, 2)
		p, l := newPeer(t, "10.0.0.1:1234", "10.0.0.2:80")
		s := newTestStack(t, l, accept(conns))
		s.verify = tunnel
		p.connect(nil)
		a := take(t, conns)
		a.conn.Close()
		if seg := p.receive(); seg.flags != tcpFin|tcpAck || seg.seq != p.ack {
			t.Fatal("not a FIN: flags ", seg.flags, ", seq ", seg.seq)
		}
		p.send(p.seq+1000, tcpSyn, nil, nil)
		if !tunnel {
			if seg := p.receive(); seg.flags != tcpSyn|tcpAck || seg.ack != p.seq+1001 {
				t.Fatal("not opened anew: flags ", seg.flags, ", ack ", seg.ack-p.seq)
			}
			continue
		}
		if seg := p.receive(); seg.flags != tcpAck || seg.ack != p.seq {
			t.Fatal("not answered with what is expected: flags ", seg.flags, ", ack ", seg.ack-p.seq)
		}
		p.silent(tcpTick / 2)
		// and it is still there: its FIN is acknowledged, and the other side closes as well
		p.ack++
		p.send(p.seq, tcpFin|tcpAck, nil, nil)
		p.seq++
		if seg := p.receive(); seg.flags != tcpAck || seg.ack != p.seq {
			t.Fatal("the FIN is not acknowledged: flags ", seg.flags, ", ack ", seg.ack-p.seq)
		}
		forgotten(t, s)
	}
}

// A UDP packet starts a connection, which answers from any address, and an echo request is answered.
func TestUDPAndICMP(t *testing.T) {
	for _, test := range []struct{ src, dst, other string }{
		{"10.0.0.1:1234", "10.0.0.2:53", "10.0.0.3:5353"},
		{"[fd00::1]:1234", "[fd00::2]:53", "[fd00::3]:5353"},
	} {
		conns := make(chan accepted, 1)
		p, l := newPeer(t, test.src, test.dst)
		newTestStack(t, l, accept(conns))

		var b [ipv6HeaderSize + udpHeaderSize]byte
		n := putIPHeader(b[:], protoUDP, p.src.Addr(), p.dst.Addr())
		u := b[n : n+udpHeaderSize]
		binary.BigEndian.PutUint16(u, p.src.Port())
		binary.BigEndian.PutUint16(u[2:], p.dst.Port())
		binary.BigEndian.PutUint16(u[4:], udpHeaderSize+3)
		setIPLength(b[:n], n+udpHeaderSize+3)
		l.in <- append(b[:n+udpHeaderSize:n+udpHeaderSize], "abc"...)
		a := take(t, conns)
		mb, err := a.conn.(buf.Reader).ReadMultiBuffer()
		if err != nil || mb.String() != "abc" || *mb[0].UDP != a.dest || a.dest.NetAddr() != test.dst || a.conn.RemoteAddr().String() != test.src {
			t.Fatal("read ", mb.String(), " from ", a.conn.RemoteAddr(), " to ", a.dest, ", error: ", err)
		}
		buf.ReleaseMulti(mb)

		for _, from := range []string{test.dst, test.other} {
			answer := buf.FromBytes([]byte("defg"))
			source := net.UDPDestination(net.ParseAddress(netip.MustParseAddrPort(from).Addr().String()), net.Port(netip.MustParseAddrPort(from).Port()))
			answer.UDP = &source
			if err := a.conn.(buf.Writer).WriteMultiBuffer(buf.MultiBuffer{answer}); err != nil {
				t.Fatal(err)
			}
			raw := p.packet()
			packet, ok := parsePacket(raw)
			u := packet.payload
			// the system may have to split it on the way to where it goes
			if !ok || raw[0]>>4 == 4 && raw[6] != 0 || packet.proto != protoUDP || netip.AddrPortFrom(packet.src, binary.BigEndian.Uint16(u)).String() != from ||
				netip.AddrPortFrom(packet.dst, binary.BigEndian.Uint16(u[2:])) != p.src || string(u[udpHeaderSize:]) != "defg" {
				t.Fatal("wrong packet from ", from, ": ", packet)
			}
			var ip [ipv6HeaderSize]byte
			if size := putIPHeader(ip[:], protoUDP, packet.src, packet.dst); transportChecksum(ip[:size], protoUDP, u, nil) != 0 {
				t.Fatal("wrong checksum of the packet from ", from)
			}
		}
		a.conn.Close()

		proto, request, reply := byte(protoICMPv4), byte(8), byte(0)
		if p.src.Addr().Is6() {
			proto, request, reply = protoICMPv6, 128, 129
		}
		n = putIPHeader(b[:], proto, p.src.Addr(), p.dst.Addr())
		setIPLength(b[:n], n+12)
		l.in <- append(b[:n:n], request, 0, 0, 0, 1, 2, 3, 4, 'a', 'b', 'c', 'd')
		packet, ok := parsePacket(p.packet())
		m := packet.payload
		if !ok || packet.proto != proto || packet.src != p.dst.Addr() || packet.dst != p.src.Addr() || m[0] != reply || string(m[4:]) != "\x01\x02\x03\x04abcd" {
			t.Fatal("wrong echo reply: ", packet)
		}
		var ip [ipv6HeaderSize]byte
		size := putIPHeader(ip[:], proto, packet.src, packet.dst)
		if proto == protoICMPv4 && checksum(sum(m, 0)) != 0 || proto == protoICMPv6 && transportChecksum(ip[:size], proto, m, nil) != 0 {
			t.Fatal("wrong checksum of the echo reply")
		}
	}
}

// newDialStack is a stack that opens connections from its addresses and takes none
func newDialStack(t *testing.T, l *link, addresses ...string) *stack {
	s := newTestStack(t, l, nil)
	for _, a := range addresses {
		s.addresses = append(s.addresses, netip.MustParseAddr(a))
	}
	return s
}

// dialed is what DialTCP returns
type dialed struct {
	conn net.Conn
	err  error
}

func dial(ctx context.Context, s *stack, remote netip.AddrPort) chan dialed {
	result := make(chan dialed, 1)
	go func() {
		conn, err := s.DialTCP(ctx, remote)
		result <- dialed{conn, err}
	}()
	return result
}

// A connection that is opened from here offers what the stack has in its SYN, takes what the answer says of it,
// and is then like one that the system opened.
func TestTCPDial(t *testing.T) {
	for _, test := range []struct {
		remote, local     string
		expected, options []byte
		window            uint16
	}{
		{"10.0.0.1:80", "10.0.0.2", []byte{2, 4, 5, 0xb4, 1, 1, 4, 2, 1, 3, 3, tcpWindowShift}, []byte{2, 4, 2, 0, 4, 2, 1, 3, 3, 7, 0, 0}, tcpWindow >> tcpWindowShift},
		{"[fd00::1]:80", "fd00::2", []byte{2, 4, 5, 0xa0, 1, 1, 4, 2, 1, 3, 3, tcpWindowShift}, nil, 0xffff},
	} {
		p, l := newPeer(t, test.remote, "10.0.0.2:0")
		s := newDialStack(t, l, "10.0.0.2", "fd00::2")
		result := dial(context.Background(), s, p.src)
		syn, _ := p.dialed()
		if syn.flags != tcpSyn || syn.window != 0xffff || !bytes.Equal(syn.options, test.expected) || p.dst.Addr().String() != test.local || p.dst.Port() < 1<<15 {
			t.Fatal("not a SYN from ", test.local, ": flags ", syn.flags, ", window ", syn.window, ", options ", syn.options, ", from ", p.dst)
		}
		p.ack = syn.seq + 1
		p.send(p.seq, tcpSyn|tcpAck, test.options, nil)
		p.seq++
		d := <-result
		if d.err != nil || d.conn.RemoteAddr().String() != test.remote || d.conn.LocalAddr().String() != p.dst.String() {
			t.Fatal("connection from ", d.conn.LocalAddr(), " to ", d.conn.RemoteAddr(), ", error: ", d.err)
		}
		// the time that the answer took is taken, the next that is timed is what is written
		c := d.conn.(*tcpConn)
		c.mu.Lock()
		timed := c.timedAt.IsZero()
		c.mu.Unlock()
		if !timed {
			t.Fatal("the time that the answer took is not taken")
		}
		// the answer is acknowledged by then, the other side does not wait for a timer to open its end
		select {
		case b := <-p.sent:
			if s := p.segment(b); s.flags != tcpAck || s.seq != p.ack || s.ack != p.seq || s.window != test.window || len(s.options) != 0 {
				t.Fatal("the answer is not acknowledged: flags ", s.flags, ", seq ", s.seq, ", ack ", s.ack, ", window ", s.window)
			}
		default:
			t.Fatal("the answer is not acknowledged yet")
		}

		write(t, d.conn, []byte("abc"))
		packet := p.packet()
		if s := p.segment(packet); string(s.payload) != "abc" || s.seq != p.ack || s.flags != tcpAck|tcpPsh {
			t.Fatal("wrong segment: seq ", s.seq, ", flags ", s.flags, ", payload ", s.payload)
		}
		// a router that says it found no way for it does not end a connection that is open
		p.icmp(unreachable(packet, 1))
		p.ack += 3
		p.send(p.seq, tcpAck|tcpPsh, nil, []byte("def"))
		p.seq += 3
		read(t, d.conn, "def")
		if s := p.receive(); s.flags != tcpAck || s.ack != p.seq {
			t.Fatal("not acknowledged: flags ", s.flags, ", ack ", s.ack)
		}
		d.conn.Close()
		if s := p.receive(); s.flags != tcpFin|tcpAck || s.seq != p.ack {
			t.Fatal("not a FIN: flags ", s.flags, ", seq ", s.seq)
		}
		p.ack++
		p.send(p.seq, tcpFin|tcpAck, nil, nil)
		p.seq++
		if s := p.receive(); s.flags != tcpAck || s.ack != p.seq {
			t.Fatal("the FIN is not acknowledged: flags ", s.flags, ", ack ", s.ack)
		}
		forgotten(t, s)
	}
}

// A SYN that is not answered is sent again. The wait for its answer ends when the other side refuses it,
// and when the one who waits gives up.
func TestTCPDialUnanswered(t *testing.T) {
	p, l := newPeer(t, "10.0.0.1:80", "10.0.0.2:0")
	s := newDialStack(t, l, "10.0.0.2")
	if _, err := s.DialTCP(context.Background(), netip.MustParseAddrPort("[fd00::1]:80")); err == nil {
		t.Fatal("a connection from no address")
	}

	// an address of IPv4 may come in the form that IPv6 has for it
	result := dial(context.Background(), s, netip.AddrPortFrom(netip.AddrFrom16(p.src.Addr().As16()), p.src.Port()))
	syn, _ := p.dialed()
	// a SYN of the other side is not an answer, and nothing to refuse either
	p.send(p.seq, tcpSyn, nil, nil)
	if again := p.receive(); again.flags != tcpSyn || again.seq != syn.seq || !bytes.Equal(again.options, syn.options) {
		t.Fatal("not the SYN again: flags ", again.flags, ", seq ", again.seq, ", options ", again.options)
	}
	// what answers another SYN, of a connection that the other side has from before, is told that there is none
	p.ack = syn.seq + 100
	p.send(p.seq, tcpSyn|tcpAck, nil, nil)
	if s := p.receive(); s.flags != tcpRst || s.seq != p.ack {
		t.Fatal("not a reset: flags ", s.flags, ", seq ", s.seq)
	}
	// and so is a reset for another SYN
	p.send(p.seq, tcpRst|tcpAck, nil, nil)
	p.ack = syn.seq + 1
	p.send(p.seq, tcpRst|tcpAck, nil, nil)
	if d := <-result; d.err != errTCPRefused {
		t.Fatal("not refused: ", d.err)
	}
	forgotten(t, s)

	ctx, cancel := context.WithCancel(context.Background())
	result = dial(ctx, s, p.src)
	syn, _ = p.dialed()
	cancel()
	if d := <-result; d.err != context.Canceled {
		t.Fatal("not given up: ", d.err)
	}
	forgotten(t, s)
	// the answer comes too late
	p.ack = syn.seq + 1
	p.send(p.seq, tcpSyn|tcpAck, nil, nil)
	if s := p.receive(); s.flags != tcpRst || s.seq != p.ack {
		t.Fatal("not a reset: flags ", s.flags, ", seq ", s.seq)
	}

	// an answer to a SYN that was sent again opens the connection as well, the time that it took is not known then
	result = dial(context.Background(), s, p.src)
	syn, _ = p.dialed()
	p.receive()
	p.ack = syn.seq + 1
	p.send(p.seq, tcpSyn|tcpAck, nil, nil)
	d := <-result
	if d.err != nil {
		t.Fatal(d.err)
	}
	c := d.conn.(*tcpConn)
	c.mu.Lock()
	srtt, stalled, retransmits := c.srtt, c.stalled, c.retransmits
	c.mu.Unlock()
	if srtt != 0 || stalled != 0 || retransmits != 0 {
		t.Fatal("after the answer: round trip ", srtt, ", ", stalled, " ticks without one, sent again ", retransmits, " times")
	}
	d.conn.Close()

	// a router on the way that cannot deliver the SYN ends the wait as well, whatever it says is unreachable
	for _, test := range []struct {
		remote string
		code   byte
	}{
		{"10.0.0.1:80", 1},
		{"10.0.0.1:80", 3},
		{"[fd00::1]:80", 0},
		{"[fd00::1]:80", 4},
	} {
		p, l := newPeer(t, test.remote, "10.0.0.2:0")
		s := newDialStack(t, l, "10.0.0.2", "fd00::2")
		result := dial(context.Background(), s, p.src)
		_, packet := p.dialed()
		// not when it says so about another SYN
		other := bytes.Clone(packet)
		other[len(other)-tcpHeaderSize-12+7]++
		p.icmp(unreachable(other, test.code))
		select {
		case d := <-result:
			t.Fatal("not waited for anymore: ", d.err)
		case <-time.After(50 * time.Millisecond):
		}
		p.icmp(unreachable(packet, test.code))
		if d := <-result; d.err != errTCPUnreachable {
			t.Fatal("still waited for: ", d.err)
		}
		forgotten(t, s)
	}
}

// A UDP port that is opened from here sends to anyone and takes what anyone sends to it.
// A stack that only opens connections takes none.
func TestUDPDial(t *testing.T) {
	for _, test := range []struct{ remote, other, local, across, acrossLocal string }{
		{"10.0.0.1:53", "10.0.0.3:5353", "10.0.0.2", "[fd00::9]:9", "fd00::2"},
		{"[fd00::1]:53", "[fd00::3]:5353", "fd00::2", "10.0.0.9:9", "10.0.0.2"},
	} {
		p, l := newPeer(t, test.remote, "10.0.0.2:0")
		s := newDialStack(t, l, "10.0.0.2", "fd00::2")
		conn, err := s.DialUDP()
		if err != nil {
			t.Fatal(err)
		}
		local := netip.AddrPortFrom(netip.MustParseAddr(test.local), netip.MustParseAddrPort(conn.LocalAddr().String()).Port())
		if local.Port() < 1<<15 {
			t.Fatal("a port on ", local)
		}
		b := make([]byte, 100)
		numbers := map[netip.AddrPort]map[uint16]bool{}
		for _, to := range []netip.AddrPort{p.src, netip.MustParseAddrPort(test.other), p.src} {
			if numbers[to] == nil {
				numbers[to] = map[uint16]bool{}
			}
			// an address of IPv4 may come in the form that IPv6 has for it
			if _, err := conn.WriteTo([]byte("abc"), &net.UDPAddr{IP: net.IP(to.Addr().AsSlice()).To16(), Port: int(to.Port())}); err != nil {
				t.Fatal(err)
			}
			raw := p.packet()
			// a link on the way may split it, and tells by the number what to put together
			if raw[0]>>4 == 4 && (raw[6] != 0 || checksum(sum(raw[:ipv4HeaderSize], 0)) != 0 || numbers[to][binary.BigEndian.Uint16(raw[4:])]) {
				t.Fatal("wrong header of the packet to ", to, ": ", raw[:ipv4HeaderSize])
			}
			numbers[to][binary.BigEndian.Uint16(raw[4:])] = true
			packet, ok := parsePacket(raw)
			u := packet.payload
			if !ok || packet.proto != protoUDP || netip.AddrPortFrom(packet.src, binary.BigEndian.Uint16(u)) != local ||
				netip.AddrPortFrom(packet.dst, binary.BigEndian.Uint16(u[2:])) != to || string(u[udpHeaderSize:]) != "abc" {
				t.Fatal("wrong packet to ", to, ": ", packet)
			}
			var ip [ipv6HeaderSize]byte
			if size := putIPHeader(ip[:], protoUDP, packet.src, packet.dst); transportChecksum(ip[:size], protoUDP, u, nil) != 0 {
				t.Fatal("wrong checksum of the packet to ", to)
			}
			// what is for another port is for nobody
			p.udp(to, netip.AddrPortFrom(local.Addr(), local.Port()^1), "none")
			p.udp(to, local, "defg")
			if n, from, err := conn.ReadFrom(b); err != nil || string(b[:n]) != "defg" || from.String() != to.String() {
				t.Fatal("read ", string(b[:n]), " from ", from, ", error: ", err)
			}
		}
		// the port is one on the address of the other family as well
		across, acrossLocal := netip.MustParseAddrPort(test.across), netip.AddrPortFrom(netip.MustParseAddr(test.acrossLocal), local.Port())
		if _, err := conn.WriteTo([]byte("abc"), &net.UDPAddr{IP: across.Addr().AsSlice(), Port: int(across.Port())}); err != nil {
			t.Fatal(err)
		}
		if packet, ok := parsePacket(p.packet()); !ok || packet.proto != protoUDP || packet.dst != across.Addr() ||
			netip.AddrPortFrom(packet.src, binary.BigEndian.Uint16(packet.payload)) != acrossLocal {
			t.Fatal("wrong packet to ", across, ": ", packet)
		}
		p.udp(across, acrossLocal, "hij")
		if n, from, err := conn.ReadFrom(b); err != nil || string(b[:n]) != "hij" || from.String() != across.String() {
			t.Fatal("read ", string(b[:n]), " from ", from, ", error: ", err)
		}

		// a stack that takes no connections is one host: it answers a ping of its address and of no other
		l.in <- ping(p.src.Addr(), netip.MustParseAddrPort(test.other).Addr())
		l.in <- ping(p.src.Addr(), local.Addr())
		if packet, ok := parsePacket(p.packet()); !ok || packet.src != local.Addr() || packet.dst != p.src.Addr() || packet.payload[0]&^129 != 0 {
			t.Fatal("wrong echo reply: ", packet)
		}
		p.silent(20 * time.Millisecond)

		conn.Close()
		p.udp(p.src, local, "late")
		if _, _, err := conn.ReadFrom(b); err == nil {
			t.Fatal("read from a closed port")
		}
		s.mu.Lock()
		ports := len(s.sockets)
		s.mu.Unlock()
		if ports != 0 {
			t.Fatal("ports left in the stack: ", ports)
		}
		// a port that is open when the stack is closed has nothing more to read either
		left, err := s.DialUDP()
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			s.Close()
			if _, _, err := left.ReadFrom(b); err == nil {
				t.Fatal("read from a port of a closed stack")
			}
			if _, err := s.DialUDP(); err != io.ErrClosedPipe {
				t.Fatal("a port on a closed stack: ", err)
			}
			if _, err := s.DialTCP(context.Background(), p.src); err != io.ErrClosedPipe {
				t.Fatal("a connection from a closed stack: ", err)
			}
		}()

		p.dst = netip.AddrPortFrom(local.Addr(), 80)
		p.send(p.seq, tcpSyn, nil, nil)
		if s := p.receive(); s.flags != tcpRst|tcpAck || s.ack != p.seq+1 {
			t.Fatal("not a reset: flags ", s.flags, ", ack ", s.ack)
		}
		forgotten(t, s)
	}
}

// When a link on the way does not take a segment, the connection goes on with smaller ones.
func TestTCPTooLarge(t *testing.T) {
	for _, test := range []struct {
		src, dst string
		mtu, mss int
		// the router has the packet with options in its header
		options bool
	}{
		{"10.0.0.1:1234", "10.0.0.2:80", 1000, 960, false},
		{"10.0.0.1:1234", "10.0.0.2:80", 1000, 960, true},
		{"10.0.0.1:1234", "10.0.0.2:80", 100, ipv4SmallestMTU - ipv4HeaderSize - tcpHeaderSize, false},
		{"[fd00::1]:1234", "[fd00::2]:80", 1300, 1240, false},
		{"[fd00::1]:1234", "[fd00::2]:80", 100, ipv6SmallestMTU - ipv6HeaderSize - tcpHeaderSize, false},
	} {
		conns := make(chan accepted, 1)
		p, l := newPeer(t, test.src, test.dst)
		newTestStack(t, l, accept(conns))
		p.connect(nil)
		a := take(t, conns)

		sent := make([]byte, 3000)
		rand.Read(sent)
		write(t, a.conn, sent)
		packet := p.packet()
		first := p.segment(packet)
		for size := len(first.payload); size < len(sent); {
			size += len(p.receive().payload)
		}
		// said about something that was not sent, it changes nothing
		other := bytes.Clone(packet)
		binary.BigEndian.PutUint32(other[len(other)-len(first.payload)-tcpHeaderSize+4:], first.seq-1)
		p.icmp(tooLarge(other, test.mtu))
		// nor is a message read that is cut short, or that has less of the packet than the numbers of its segment
		message := tooLarge(packet, test.mtu)
		for _, size := range []int{4, 8, 16, len(message) - 1} {
			p.icmp(message[:size])
		}
		p.silent(50 * time.Millisecond)

		if test.options {
			message = append(append(append(message[:8:8], packet[:ipv4HeaderSize]...), 1, 1, 1, 1), packet[ipv4HeaderSize:ipv4HeaderSize+8]...)
			message[8]++
		}
		// none of what is on its way fits. Its first segment comes again at once and the others as that is
		// acknowledged, so that one who says so again and again is not sent all of it every time
		p.icmp(message)
		var received []byte
		for len(received) < len(sent) {
			s := p.receive()
			if len(s.payload) > test.mss || s.seq != p.ack {
				t.Fatal("a segment of ", len(s.payload), " bytes at ", s.seq-p.ack, " past what is acknowledged, expected ", test.mss, " at most at 0")
			}
			if len(received) == 0 {
				p.silent(50 * time.Millisecond)
				// and its answer is waited for from when it was sent again
				c := a.conn.(*tcpConn)
				c.mu.Lock()
				waited := !c.headAt.IsZero()
				c.mu.Unlock()
				if !waited {
					t.Fatal("the time when the first segment was sent again is not kept")
				}
			}
			received = append(received, s.payload...)
			p.ack += uint32(len(s.payload))
			p.send(p.seq, tcpAck, nil, nil)
		}
		if !bytes.Equal(received, sent) {
			t.Fatal("sent something else again")
		}
		// and what is written from now on is as small
		write(t, a.conn, sent)
		if s := p.receive(); len(s.payload) != test.mss {
			t.Fatal("a segment of ", len(s.payload), " bytes, expected ", test.mss)
		}
	}
}

// With the times of RFC 7323 every segment carries the time of this side and the last one of the other side that
// came where the stream goes on. A segment has room for less then, and what is held is told in one block less.
func TestTCPStamps(t *testing.T) {
	stamps := func(s segment) (value, echo uint32, rest []byte) {
		t.Helper()
		if len(s.options) < tcpStamps || !bytes.Equal(s.options[:4], []byte{1, 1, 8, 10}) {
			t.Fatal("no times in the options ", s.options)
		}
		return binary.BigEndian.Uint32(s.options[4:]), binary.BigEndian.Uint32(s.options[8:]), s.options[tcpStamps:]
	}
	stamped := func(value, echo uint32, options ...byte) []byte {
		return append(binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32([]byte{1, 1, 8, 10}, value), echo), options...)
	}
	const room = testMTU - ipv4HeaderSize - tcpHeaderSize

	conns := make(chan accepted, 1)
	p, l := newPeer(t, "10.0.0.1:1234", "10.0.0.2:80")
	newTestStack(t, l, accept(conns)).stamps = true
	p.send(p.seq, tcpSyn, stamped(100, 0, 2, 4, 5, 0xb4, 4, 2, 0, 0), nil)
	p.seq++
	s := p.receive()
	own, echo, rest := stamps(s)
	if s.flags != tcpSyn|tcpAck || s.ack != p.seq || echo != 100 || !bytes.Equal(rest, []byte{2, 4, 5, 0xb4, 1, 1, 4, 2}) {
		t.Fatal("not an answer with the time of the SYN: flags ", s.flags, ", options ", s.options)
	}
	p.ack = s.seq + 1
	p.send(p.seq, tcpAck, stamped(101, own), nil)
	a := take(t, conns)

	// a segment has that much less room, also when a link on the way takes less. The time of this side goes on
	time.Sleep(2 * time.Millisecond)
	write(t, a.conn, make([]byte, testMTU))
	packet := p.packet()
	s = p.segment(packet)
	if value, echo, rest := stamps(s); len(s.payload) != room-tcpStamps || echo != 101 || int32(value-own) <= 0 || len(rest) != 0 {
		t.Fatal("a segment of ", len(s.payload), " bytes with options ", s.options)
	}
	if s = p.receive(); len(s.payload) != testMTU-room+tcpStamps {
		t.Fatal("the rest is ", len(s.payload), " bytes")
	}
	p.icmp(tooLarge(packet, 1000))
	if s = p.receive(); len(s.payload) != 1000-ipv4HeaderSize-tcpHeaderSize-tcpStamps || s.seq != p.ack {
		t.Fatal("a segment of ", len(s.payload), " bytes at ", s.seq-p.ack, " for a link that takes 1000")
	}
	p.ack += testMTU
	p.send(p.seq, tcpAck, stamped(102, own), nil)

	// the time that is sent back is not the one of a segment that waits for another
	p.send(p.seq+3, tcpAck, stamped(110, own), []byte("def"))
	s = p.receive()
	if _, echo, rest := stamps(s); s.ack != p.seq || echo != 102 || !bytes.Equal(rest, binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32([]byte{1, 1, 5, 10}, p.seq+3), p.seq+6)) {
		t.Fatal("ack ", s.ack-p.seq, " past what was sent, options ", s.options)
	}
	// nor an older one that comes late
	p.send(p.seq, tcpAck, stamped(90, own), []byte("abc"))
	p.seq += 6
	s = p.receive()
	if _, echo, rest := stamps(s); s.ack != p.seq || echo != 102 || len(rest) != 0 {
		t.Fatal("ack ", s.ack-p.seq, " past what was sent, options ", s.options)
	}
	read(t, a.conn, "abcdef")
	p.send(p.seq, tcpAck, stamped(111, own), []byte("g"))
	p.seq++
	read(t, a.conn, "g")
	s = p.receive()
	if _, echo, _ := stamps(s); s.ack != p.seq || echo != 111 {
		t.Fatal("ack ", s.ack-p.seq, " past what was sent, options ", s.options)
	}
	// the one that fills a hole is acknowledged at once, with its own time
	p.send(p.seq+3, tcpAck, stamped(120, own), []byte("jkl"))
	p.receive()
	p.send(p.seq, tcpAck, stamped(115, own), []byte("hij"))
	p.seq += 6
	s = p.receive()
	if _, echo, _ := stamps(s); s.ack != p.seq || echo != 115 {
		t.Fatal("ack ", s.ack-p.seq, " past what was sent, options ", s.options)
	}
	// of two that one acknowledgment is for, it is the time of the first
	p.silent(2 * tcpTick)
	p.send(p.seq, tcpAck, stamped(130, own), []byte("m"))
	p.send(p.seq+1, tcpAck, stamped(131, own), []byte("n"))
	p.seq += 2
	s = p.receive()
	if _, echo, _ := stamps(s); s.ack != p.seq || echo != 130 {
		t.Fatal("ack ", s.ack-p.seq, " past what was sent, options ", s.options)
	}
	// times that are not whole are none
	p.send(p.seq, tcpAck, []byte{8, 6, 0, 0, 2, 0, 0, 0}, []byte("o"))
	p.seq++
	s = p.receive()
	if _, echo, _ := stamps(s); s.ack != p.seq || echo != 130 {
		t.Fatal("ack ", s.ack-p.seq, " past what was sent, options ", s.options)
	}
	// three blocks of what is held fit next to the times
	for i := range uint32(4) {
		p.send(p.seq+3+6*i, tcpAck, stamped(132, own), []byte("xyz"))
		s = p.receive()
	}
	last, _, rest := stamps(s)
	if len(rest) != 4+3*8 {
		t.Fatal("what is held is told with ", s.options)
	}
	// what is sent while a segment is on its way to the tun has the time of that one, whichever gets there first
	c := a.conn.(*tcpConn)
	c.mu.Lock()
	c.sending = true
	time.Sleep(2 * time.Millisecond)
	c.send(c.sndNxt, tcpAck, nil, nil)
	c.sending = false
	c.mu.Unlock()
	if value, _, _ := stamps(p.receive()); value != last {
		t.Fatal("a time ", value-last, " ms after the one of the segment that is being written")
	}

	// a SYN with times that are not whole does not offer them
	q, l := newPeer(t, "10.0.0.1:1235", "10.0.0.2:80")
	newTestStack(t, l, accept(conns)).stamps = true
	if options := q.connect([]byte{8, 6, 0, 0, 2, 0, 0, 0}); !bytes.Equal(options, []byte{2, 4, 5, 0xb4}) {
		t.Fatal("times taken from a SYN that has none: ", options)
	}

	// a connection that is opened from here offers the times, and has them if the answer does
	bases := []uint32{own}
	for _, answered := range []bool{true, false} {
		p, l := newPeer(t, "10.0.0.1:80", "10.0.0.2:0")
		dialing := newDialStack(t, l, "10.0.0.2")
		dialing.stamps = true
		result := dial(context.Background(), dialing, p.src)
		syn, _ := p.dialed()
		own, echo, rest := stamps(syn)
		if syn.flags != tcpSyn || echo != 0 || !bytes.Equal(rest, []byte{2, 4, 5, 0xb4, 1, 1, 4, 2, 1, 3, 3, tcpWindowShift}) {
			t.Fatal("not a SYN that offers the times: flags ", syn.flags, ", options ", syn.options)
		}
		// every connection starts its time somewhere else
		for _, other := range bases {
			if apart := int32(own - other); apart > -5000 && apart < 5000 {
				t.Fatal("the time of a connection is ", apart, " ms from the one of another")
			}
		}
		bases = append(bases, own)
		p.ack = syn.seq + 1
		var options []byte
		if answered {
			options = stamped(200, own)
		}
		p.send(p.seq, tcpSyn|tcpAck, options, nil)
		p.seq++
		d := <-result
		if d.err != nil {
			t.Fatal(d.err)
		}
		ack := p.receive()
		write(t, d.conn, make([]byte, testMTU))
		s := p.receive()
		if answered {
			if _, echo, _ := stamps(ack); echo != 200 || len(s.payload) != room-tcpStamps {
				t.Fatal("options ", ack.options, ", then a segment of ", len(s.payload), " bytes")
			}
		} else if len(ack.options) != 0 || len(s.options) != 0 || len(s.payload) != room {
			t.Fatal("options ", ack.options, ", then a segment of ", len(s.payload), " bytes with ", s.options)
		}
	}
}

// Two stacks, one that opens connections and one that takes them, with a link between them that loses packets
// both ways: what is sent comes back.
func TestTCPEcho(t *testing.T) {
	for _, test := range []struct {
		name string
		// one packet of lose is lost
		lose int
		size int
		// the tun of the one that takes the connections takes segments that are larger than its MTU
		segments bool
		// the segments carry the times of both sides
		stamps bool
	}{
		{"lossless", 0, 16 << 20, false, false},
		{"lossy", 100, 4 << 20, false, false},
		{"very lossy", 20, 512 << 10, false, false},
		{"lossless, large segments", 0, 16 << 20, true, false},
		{"lossy, large segments", 100, 4 << 20, true, false},
		{"lossy, times", 100, 4 << 20, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			random := mrand.New(mrand.NewPCG(2, uint64(test.lose)))
			var mu sync.Mutex
			to := func(l *link) func(b []byte) {
				return func(b []byte) {
					mu.Lock()
					lost := test.lose != 0 && random.IntN(test.lose) == 0
					mu.Unlock()
					if !lost {
						select {
						case l.in <- b:
						default:
							// as a tun does when its queue is full
						}
					}
				}
			}
			near, far := newLink(), newLink()
			near.out, far.out = to(far), to(near)
			far.segments = test.segments
			server := newTestStack(t, far, echo)
			client := newDialStack(t, near, "10.0.0.1", "fd00::1")
			server.stamps, client.stamps = test.stamps, test.stamps

			for _, remote := range []string{"10.0.0.2:80", "[fd00::2]:80"} {
				conn, err := client.DialTCP(context.Background(), netip.MustParseAddrPort(remote))
				if err != nil {
					t.Fatal(err)
				}
				sent := make([]byte, test.size)
				rand.Read(sent)
				go conn.Write(sent)
				received := make([]byte, len(sent))
				done := make(chan error, 1)
				go func() {
					_, err := io.ReadFull(conn, received)
					done <- err
				}()
				select {
				case err := <-done:
					if err != nil || !bytes.Equal(received, sent) {
						t.Fatal("received something else than what was sent, error: ", err)
					}
				case <-time.After(2 * time.Minute):
					t.Fatal("what was sent did not come back")
				}
				conn.Close()
				forgotten(t, client)
				forgotten(t, server)
			}
		})
	}
}

// split cuts a packet as a link that takes less does: into fragments with size bytes of what follows the IP header
func split(packet []byte, size int, id uint32) [][]byte {
	n := ipv4HeaderSize
	if packet[0]>>4 == 6 {
		n = ipv6HeaderSize
	}
	var fragments [][]byte
	for data, offset := packet[n:], 0; offset < len(data); offset += size {
		end := min(offset+size, len(data))
		f := bytes.Clone(packet[:n])
		if n == ipv6HeaderSize {
			at := uint16(offset)
			if end < len(data) {
				at |= 1
			}
			f[6] = protoFragment
			f = binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint16(append(f, packet[6], 0), at), id)
		} else {
			at := uint16(offset / 8)
			if end < len(data) {
				at |= 0x2000
			}
			binary.BigEndian.PutUint16(f[4:], uint16(id))
			binary.BigEndian.PutUint16(f[6:], at)
		}
		f = append(f, data[offset:end]...)
		setIPLength(f[:n], len(f))
		fragments = append(fragments, f)
	}
	return fragments
}

// joined takes the fragments of a packet that the stack wrote, checks them, and returns the packet
func (p *peer) joined() []byte {
	p.t.Helper()
	var header, data []byte
	number := p.number
	for {
		b := p.packet()
		n, at, id, more := ipv4HeaderSize, 0, uint32(0), false
		if b[0]>>4 == 6 {
			n = ipv6HeaderSize
			if b[6] != protoFragment || int(binary.BigEndian.Uint16(b[4:])) != len(b)-n {
				p.t.Fatal("not a fragment: ", b[:n])
			}
			f := b[n : n+fragmentHeaderSize]
			header = bytes.Clone(b[:n])
			header[6] = f[0]
			at, more, id = int(binary.BigEndian.Uint16(f[2:])&^7), f[3]&1 != 0, binary.BigEndian.Uint32(f[4:])
			n += fragmentHeaderSize
		} else {
			if checksum(sum(b[:n], 0)) != 0 || int(binary.BigEndian.Uint16(b[2:])) != len(b) {
				p.t.Fatal("wrong header of a fragment: ", b[:n])
			}
			f := binary.BigEndian.Uint16(b[6:])
			header = bytes.Clone(b[:n])
			header[6], header[7] = 0, 0
			at, more, id = int(f&0x1fff)*8, f&0x2000 != 0, uint32(binary.BigEndian.Uint16(b[4:]))
		}
		if len(data) == 0 {
			if id == number {
				p.t.Fatal("the number of the last packet again: ", id)
			}
			number, p.number = id, id
		}
		if len(b) > testMTU || at != len(data) || id != number || more && (len(b)-n)%8 != 0 || more && len(b)+8 <= testMTU {
			p.t.Fatal("a fragment of ", len(b), " bytes at ", at, " with the number ", id, ", expected at ", len(data), " with ", number)
		}
		data = append(data, b[n:]...)
		if !more {
			setIPLength(header, len(header)+len(data))
			return append(header, data...)
		}
	}
}

// A packet that is larger than a link on its way comes in fragments, in any order, and leaves in fragments.
func TestFragments(t *testing.T) {
	for _, test := range []struct{ src, dst string }{
		{"10.0.0.1:1234", "10.0.0.2:53"},
		{"[fd00::1]:1234", "[fd00::2]:53"},
	} {
		conns := make(chan accepted, 1)
		p, l := newPeer(t, test.src, test.dst)
		s := newTestStack(t, l, accept(conns))
		sent := make([]byte, 3000)
		rand.Read(sent)
		receive := func(a accepted, expected []byte) {
			t.Helper()
			mb, err := a.conn.(buf.Reader).ReadMultiBuffer()
			if err != nil || len(mb) != 1 || !bytes.Equal(mb[0].Bytes(), expected) {
				t.Fatal("read ", mb.Len(), " bytes, expected the ", len(expected), " that were sent, error: ", err)
			}
			buf.ReleaseMulti(mb)
		}

		whole := summed(udpPacket(p.src, p.dst, sent))
		parts := split(whole, 1024, 7)
		for _, i := range []int{2, 0, 0, 1} {
			l.in <- parts[i]
		}
		a := take(t, conns)
		receive(a, sent)

		if err := a.conn.(buf.Writer).WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(sent)}); err != nil {
			t.Fatal(err)
		}
		packet, ok := parsePacket(p.joined())
		u := packet.payload
		if !ok || packet.fragment || packet.proto != protoUDP || netip.AddrPortFrom(packet.src, binary.BigEndian.Uint16(u)) != p.dst ||
			netip.AddrPortFrom(packet.dst, binary.BigEndian.Uint16(u[2:])) != p.src || int(binary.BigEndian.Uint16(u[4:])) != len(u) || !bytes.Equal(u[udpHeaderSize:], sent) {
			t.Fatal("wrong packet: ", packet.src, packet.dst, packet.proto, len(u))
		}
		var ip [ipv6HeaderSize]byte
		if size := putIPHeader(ip[:], protoUDP, packet.src, packet.dst); transportChecksum(ip[:size], protoUDP, u, nil) != 0 {
			t.Fatal("wrong checksum of the packet")
		}

		proto, request, reply := byte(protoICMPv4), byte(8), byte(0)
		if p.src.Addr().Is6() {
			proto, request, reply = protoICMPv6, 128, 129
		}
		n := putIPHeader(ip[:], proto, p.src.Addr(), p.dst.Addr())
		m := append([]byte{request, 0, 0, 0, 1, 2, 3, 4}, sent...)
		setIPLength(ip[:n], n+len(m))
		for _, part := range split(summed(append(ip[:n:n], m...)), 1480, 8) {
			l.in <- part
		}
		// the fragments of two packets with one number are not one packet: what is put together has its checksum looked at
		mixed := split(summed(udpPacket(p.src, p.dst, bytes.Repeat([]byte{1}, 2000))), 1024, 11)
		l.in <- mixed[0]
		l.in <- split(summed(udpPacket(p.src, p.dst, bytes.Repeat([]byte{2}, 2000))), 1024, 11)[1]
		packet, ok = parsePacket(p.joined())
		m = packet.payload
		if !ok || packet.proto != proto || packet.src != p.dst.Addr() || packet.dst != p.src.Addr() || m[0] != reply || !bytes.Equal(m[8:], sent) {
			t.Fatal("wrong echo reply: ", packet.src, packet.dst, packet.proto, len(m))
		}
		size := putIPHeader(ip[:], proto, packet.src, packet.dst)
		if proto == protoICMPv4 && checksum(sum(m, 0)) != 0 || proto == protoICMPv6 && transportChecksum(ip[:size], proto, m, nil) != 0 {
			t.Fatal("wrong checksum of the echo reply")
		}

		// packets whose other fragments do not come are only so many, and do not keep a later one from coming
		for id := range uint32(fragmentsMost) {
			l.in <- split(whole, 1024, 100+id)[0]
		}
		for _, part := range split(whole, 1024, 9) {
			l.in <- part
		}
		receive(a, sent)
		s.fragments.mu.Lock()
		left := len(s.fragments.packets)
		s.fragments.mu.Unlock()
		if left != fragmentsMost-1 {
			t.Fatal("packets that are still waited for: ", left)
		}
	}
}

// An MTU that has no room for a fragment is one that nothing larger than it is written to.
func TestFragmentsWithoutRoom(t *testing.T) {
	for _, test := range []struct {
		src, dst string
		mtu      int
	}{
		{"10.0.0.2:53", "10.0.0.1:1234", ipv4HeaderSize + 7},
		{"[fd00::2]:53", "[fd00::1]:1234", ipv6HeaderSize + fragmentHeaderSize + 7},
	} {
		l := newLink()
		l.out = func([]byte) { t.Error("a packet with an MTU of ", test.mtu) }
		s := &stack{tun: l, mtu: test.mtu}
		if err := s.sendUDP(make([]byte, 100), netip.MustParseAddrPort(test.src), netip.MustParseAddrPort(test.dst)); err == nil {
			t.Fatal("no error with an MTU of ", test.mtu)
		}
	}
}

// summed fills in the checksum of a UDP packet or an ICMP message
func summed(b []byte) []byte {
	n, proto := ipv4HeaderSize, b[9]
	if b[0]>>4 == 6 {
		n, proto = ipv6HeaderSize, b[6]
	}
	at := 2
	if proto == protoUDP {
		at = 6
	}
	m := b[n:]
	m[at], m[at+1] = 0, 0
	if proto == protoICMPv4 {
		binary.BigEndian.PutUint16(m[at:], checksum(sum(m, 0)))
	} else {
		binary.BigEndian.PutUint16(m[at:], transportChecksum(b[:n], proto, m, nil))
	}
	return b
}

// What comes through a tunnel has come a long way and is not taken with a wrong checksum.
// And nothing that is from or for this machine itself is taken from any tun.
func TestChecksumsAndLoopback(t *testing.T) {
	for _, test := range []struct {
		src, dst, loopback string
		read               []string
	}{
		{"10.0.0.1:1234", "10.0.0.2:80", "127.0.0.1:80", []string{"zero", "abc", "pad"}},
		{"[fd00::1]:1234", "[fd00::2]:80", "[::1]:80", []string{"abc", "pad"}},
	} {
		conns := make(chan accepted, 2)
		p, l := newPeer(t, test.src, test.dst)
		s := newTestStack(t, l, accept(conns))
		s.verify = true
		damaged := func(b []byte) []byte {
			b = bytes.Clone(b)
			b[len(b)-1] ^= 1
			return b
		}

		syn := p.bytes(p.seq, tcpSyn, nil, []byte{0})
		l.in <- damaged(syn)
		if syn[0]>>4 == 4 {
			header := bytes.Clone(syn)
			header[8]--
			l.in <- header
		}
		p.silent(50 * time.Millisecond)
		l.in <- syn
		if s := p.receive(); s.flags != tcpSyn|tcpAck || s.ack != p.seq+1 {
			t.Fatal("not an answer to the SYN: flags ", s.flags, ", ack ", s.ack)
		}
		p.send(p.seq+1, tcpRst, nil, nil)
		forgotten(t, s)
		if syn[0]>>4 == 4 {
			// the options of a header are a part of it
			options := append(append(bytes.Clone(syn[:ipv4HeaderSize]), 1, 1, 1, 1), syn[ipv4HeaderSize:]...)
			options[0]++
			binary.BigEndian.PutUint16(options[2:], uint16(len(options)))
			options[10], options[11] = 0, 0
			binary.BigEndian.PutUint16(options[10:], checksum(sum(options[:ipv4HeaderSize+4], 0)))
			wrong := bytes.Clone(options)
			wrong[ipv4HeaderSize] = 0
			l.in <- wrong
			p.silent(50 * time.Millisecond)
			l.in <- options
			if s := p.receive(); s.flags != tcpSyn|tcpAck || s.ack != p.seq+1 {
				t.Fatal("not an answer to the SYN: flags ", s.flags, ", ack ", s.ack)
			}
			p.send(p.seq+1, tcpRst, nil, nil)
			forgotten(t, s)
		}

		// a UDP packet may go without a checksum, but not an IPv6 one
		l.in <- udpPacket(p.src, p.dst, []byte("zero"))
		l.in <- damaged(summed(udpPacket(p.src, p.dst, []byte("abc"))))
		l.in <- summed(udpPacket(p.src, p.dst, []byte("abc")))
		// a packet may be longer than what it carries, and the checksum is of that
		padded := append(summed(udpPacket(p.src, p.dst, []byte("pad"))), 0, 0, 0, 0)
		setIPLength(padded[:len(padded)-4-3-udpHeaderSize], len(padded))
		l.in <- padded
		a := take(t, conns)
		for _, expected := range test.read {
			read(t, a.conn, expected)
		}

		proto, request := byte(protoICMPv4), byte(8)
		if p.src.Addr().Is6() {
			proto, request = protoICMPv6, 128
		}
		var ip [ipv6HeaderSize]byte
		n := putIPHeader(ip[:], proto, p.src.Addr(), p.dst.Addr())
		setIPLength(ip[:n], n+12)
		echo := summed(append(ip[:n:n], request, 0, 0, 0, 1, 2, 3, 4, 'a', 'b', 'c', 'd'))
		l.in <- damaged(echo)
		p.silent(50 * time.Millisecond)
		l.in <- echo
		if packet, ok := parsePacket(p.packet()); !ok || packet.proto != proto || string(packet.payload[4:]) != "\x01\x02\x03\x04abcd" {
			t.Fatal("wrong echo reply: ", packet)
		}

		// to this machine itself, from it, to no address, and from many at once
		loopback := netip.MustParseAddrPort(test.loopback)
		none := netip.AddrPortFrom(netip.IPv4Unspecified(), 80)
		if p.src.Addr().Is6() {
			none = netip.AddrPortFrom(netip.IPv6Unspecified(), 80)
		}
		l.in <- summed(udpPacket(netip.AddrPortFrom(p.src.Addr(), 1236), none, []byte("abc")))
		many := netip.AddrPortFrom(netip.MustParseAddr("224.0.0.1"), 1234)
		if p.src.Addr().Is6() {
			many = netip.AddrPortFrom(netip.MustParseAddr("ff02::1"), 1234)
		}
		for _, from := range []netip.AddrPort{loopback, many} {
			l.in <- summed(udpPacket(from, netip.AddrPortFrom(p.dst.Addr(), 53), []byte("abc")))
		}
		l.in <- summed(udpPacket(netip.AddrPortFrom(p.src.Addr(), 1235), loopback, []byte("abc")))
		if p.src.Addr().Is6() {
			// nor to or from an IPv6 address that stands for an IPv4 one: ::ffff:0.0.0.0 would be dialed as 0.0.0.0
			for _, to := range []string{"[::ffff:0.0.0.0]:53", "[::ffff:127.0.0.1]:53", "[::ffff:10.0.0.2]:53"} {
				l.in <- summed(udpPacket(netip.AddrPortFrom(p.src.Addr(), 1237), netip.MustParseAddrPort(to), []byte("abc")))
			}
			l.in <- summed(udpPacket(netip.MustParseAddrPort("[::ffff:10.0.0.1]:1238"), netip.AddrPortFrom(p.dst.Addr(), 53), []byte("abc")))
			dst := p.dst
			p.dst = netip.MustParseAddrPort("[::ffff:0.0.0.0]:80")
			p.send(p.seq, tcpSyn, nil, nil)
			p.dst = dst
		}
		p.dst = loopback
		p.send(p.seq, tcpSyn, nil, nil)
		p.silent(50 * time.Millisecond)
		select {
		case a := <-conns:
			t.Fatal("a connection from ", a.conn.RemoteAddr(), " to ", a.dest)
		default:
		}
	}
}

// handler is a ConnectionHandler that is a function
type handler func(net.Conn, net.Destination)

func (h handler) HandleConnection(conn net.Conn, dest net.Destination) { h(conn, dest) }

// What a stack is like depends on what it is made with.
func TestNewStack(t *testing.T) {
	l := newLink()
	made, _ := NewStack(context.Background(), StackOptions{Tun: l, MTU: testMTU}, nil)
	if s := made.(*stack); s.mtu != testMTU || s.window != tcpWindow || s.verify || s.stamps || s.segmenter != nil || s.handle != nil || s.udp != nil {
		t.Fatal("wrong stack for a tun of this machine that only opens connections: ", s)
	}
	l.segments = true
	made, _ = NewStack(context.Background(), StackOptions{Tun: l, MTU: testMTU}, handler(echo))
	if s := made.(*stack); s.window != tcpLargeWindow || s.verify || s.stamps || s.segmenter == nil || s.handle == nil || s.udp == nil {
		t.Fatal("wrong stack for a tun that takes large segments: ", s)
	}
	l.segments = false
	addresses := []netip.Addr{netip.MustParseAddr("10.0.0.2")}
	made, _ = NewStack(context.Background(), StackOptions{Tun: l, MTU: testMTU, Addresses: addresses, Remote: true}, nil)
	if s := made.(*stack); s.window != tcpLargeWindow || !s.verify || !s.stamps || s.segmenter != nil || len(s.addresses) != 1 {
		t.Fatal("wrong stack for a tunnel to another system: ", s)
	}
}

// What is opened from here gets a port that nothing else of it is on, as long as there is one.
func TestPorts(t *testing.T) {
	p, l := newPeer(t, "10.0.0.1:80", "10.0.0.2:0")
	s := newDialStack(t, l, "10.0.0.2", "fd00::2")
	// all but one are taken, UDP ports on one address or the other
	const free = 1<<15 + 1234
	udp, tcp := &udpSocket{queue: newPacketQueue(1)}, new(tcpConn)
	s.mu.Lock()
	for port := 1 << 15; port < 1<<16; port++ {
		if port != free {
			s.sockets[netip.AddrPortFrom(s.addresses[port&1], uint16(port))] = udp
			s.conns[flow{src: p.src, dst: netip.AddrPortFrom(s.addresses[0], uint16(port))}] = tcp
		}
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		for f, c := range s.conns {
			if c == tcp {
				delete(s.conns, f)
			}
		}
		s.mu.Unlock()
	}()

	conn, err := s.DialUDP()
	if err != nil || netip.MustParseAddrPort(conn.LocalAddr().String()).Port() != free {
		t.Fatal("a port that is taken: ", conn, ", error: ", err)
	}
	if _, err := s.DialUDP(); err == nil {
		t.Fatal("a port although none is left")
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := dial(ctx, s, p.src)
	if p.dialed(); p.dst.Port() != free {
		t.Fatal("a connection from a port that is taken: ", p.dst)
	}
	if _, err := s.DialTCP(context.Background(), p.src); err == nil {
		t.Fatal("a connection although no port is left")
	}
	// only for the same other side
	other := dial(ctx, s, netip.MustParseAddrPort("10.0.0.1:81"))
	p.packet()
	cancel()
	<-result
	<-other
}

// Fragments that do not fit each other are of no packet, and those of a packet are not put together
// with those of another.
func TestFragmentsThatDoNotFit(t *testing.T) {
	src, dst := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	fragment := func(from netip.Addr, proto byte, id uint32, offset, size int, more bool, fill byte) packet {
		return packet{proto: proto, src: from, dst: dst, payload: bytes.Repeat([]byte{fill}, size), fragment: true, more: more, offset: offset, id: id}
	}
	udp := func(offset, size int, more bool, fill byte) packet {
		return fragment(src, protoUDP, 1, offset, size, more, fill)
	}
	waited := func(r *reassembly) int {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.packets)
	}
	// add takes fragments, the last of which makes a packet or not
	add := func(r *reassembly, fragments ...packet) (packet, bool) {
		for _, f := range fragments[:len(fragments)-1] {
			if p, ok := r.add(f); ok {
				t.Fatal("a packet before its last fragment: ", p)
			}
		}
		return r.add(fragments[len(fragments)-1])
	}

	r := new(reassembly)
	for i, f := range []packet{
		// without anything, not a number of 8 bytes with more to come, past what an IP packet carries
		udp(0, 0, true, 1),
		udp(0, 12, true, 1),
		udp(math.MaxUint16-ipv4HeaderSize-7, 8, false, 1),
		fragment(netip.MustParseAddr("fd00::1"), protoUDP, 1, math.MaxUint16-7, 8, false, 1),
	} {
		if _, ok := r.add(f); ok || waited(r) != 0 {
			t.Fatal("a fragment that is none is waited for more of: ", i)
		}
	}
	for i, fragments := range [][]packet{
		// overlapping, a second end past the first and before it, past the end, an end before what came
		{udp(0, 16, true, 1), udp(8, 16, true, 2)},
		{udp(8, 8, false, 1), udp(16, 8, false, 2)},
		{udp(8, 8, false, 1), udp(0, 8, false, 2)},
		{udp(8, 8, false, 1), udp(16, 16, true, 2)},
		{udp(16, 8, true, 1), udp(8, 8, false, 2)},
	} {
		r := new(reassembly)
		if _, ok := add(r, fragments...); ok || waited(r) != 0 {
			t.Fatal("fragments that do not fit each other are still waited for: ", i)
		}
	}

	// one that comes twice is taken once, as it came first
	if p, ok := add(r, udp(0, 16, true, 1), udp(0, 16, true, 2), udp(16, 8, false, 3)); !ok || string(p.payload) != strings.Repeat("\x01", 16)+strings.Repeat("\x03", 8) || waited(r) != 0 {
		t.Fatal("wrong packet of a fragment that came twice: ", p, ok)
	}
	// the same number from someone else, or of another protocol, is another packet
	if p, ok := add(r, udp(0, 8, true, 1), fragment(netip.MustParseAddr("10.0.0.3"), protoUDP, 1, 8, 8, false, 2),
		fragment(src, protoICMPv4, 1, 8, 8, false, 3), udp(8, 8, false, 4)); !ok || string(p.payload) != strings.Repeat("\x01", 8)+strings.Repeat("\x04", 8) || waited(r) != 2 {
		t.Fatal("wrong packet among others with its number: ", p, ok)
	}
	// what is left of a packet whose other fragments were lost is not put together with a later one of its number
	r = new(reassembly)
	r.add(udp(0, 8, true, 1))
	r.packets[fragments{src, dst, protoUDP, 1}].since = time.Now().Add(-2 * fragmentsTime)
	if p, ok := add(r, udp(8, 8, false, 2), udp(0, 8, true, 3)); !ok || string(p.payload) != strings.Repeat("\x03", 8)+strings.Repeat("\x02", 8) {
		t.Fatal("wrong packet after one of its number was given up: ", p, ok)
	}
	// when too many are waited for, the one that is waited for the longest makes room
	r = new(reassembly)
	for id := range uint32(fragmentsMost) {
		r.add(fragment(src, protoUDP, id, 0, 8, true, 1))
	}
	r.packets[fragments{src, dst, protoUDP, 7}].since = time.Now().Add(-time.Second)
	r.add(fragment(src, protoUDP, fragmentsMost, 0, 8, true, 1))
	if r.packets[fragments{src, dst, protoUDP, 7}] != nil || r.packets[fragments{src, dst, protoUDP, fragmentsMost}] == nil || waited(r) != fragmentsMost {
		t.Fatal("not the one that was waited for the longest made room")
	}
}

// The checksum is that of the 16-bit words added one by one.
func TestChecksum(t *testing.T) {
	b := make([]byte, 5000)
	rand.Read(b)
	for size := 0; size < len(b); size += 1 + size/64 {
		expected := uint32(size)
		for i := 0; i < size; i += 2 {
			expected += uint32(b[i]) << 8
			if i+1 < size {
				expected += uint32(b[i+1])
			}
			expected = expected>>16 + expected&0xffff
		}
		if got := checksum(sum(b[:size], uint64(size))); got != ^uint16(expected) {
			t.Fatal("checksum of ", size, " bytes: ", got, ", expected ", ^uint16(expected))
		}
	}
}
