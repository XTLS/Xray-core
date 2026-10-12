package tun

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	mrand "math/rand/v2"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	gstack "gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
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
	s := &stack{ctx: context.Background(), tun: l, mtu: testMTU, window: tcpWindow, handle: handle, conns: make(map[flow]*tcpConn)}
	if l.segments {
		s.segmenter, s.window, l.wrong = l, tcpLargeWindow, t.Error
	}
	s.udp = newUdpConnectionHandler(handle, s.writeUDP)
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

// A real TCP on the other side of a tun that loses packets both ways gets back what it sent.
func TestTCPEcho(t *testing.T) {
	for _, test := range []struct {
		name string
		// one packet of lose is lost
		lose int
		size int
		// the tun takes segments that are larger than its MTU
		segments bool
	}{
		{"lossless", 0, 16 << 20, false},
		{"lossy", 100, 4 << 20, false},
		{"very lossy", 20, 512 << 10, false},
		{"lossless, large segments", 0, 16 << 20, true},
		{"lossy, large segments", 100, 4 << 20, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			l := newLink()
			l.segments = test.segments
			random := mrand.New(mrand.NewPCG(1, uint64(test.lose)))
			var mu sync.Mutex
			lost := func() bool {
				mu.Lock()
				defer mu.Unlock()
				return test.lose != 0 && random.IntN(test.lose) == 0
			}

			// the system on the other side of the tun
			system := gstack.New(gstack.Options{
				NetworkProtocols:   []gstack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
				TransportProtocols: []gstack.TransportProtocolFactory{tcp.NewProtocol},
			})
			defer system.Destroy()
			endpoint := channel.New(512, testMTU, "")
			if err := system.CreateNIC(1, endpoint); err != nil {
				t.Fatal(err)
			}
			for _, address := range []tcpip.ProtocolAddress{
				{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4([4]byte{10, 0, 0, 1}).WithPrefix()},
				{Protocol: ipv6.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom16([16]byte{0xfd, 15: 1}).WithPrefix()},
			} {
				if err := system.AddProtocolAddress(1, address, gstack.AddressProperties{}); err != nil {
					t.Fatal(err)
				}
			}
			system.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
			sack := tcpip.TCPSACKEnabled(true)
			system.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
			// without RACK: after a tail loss probe of it that is lost too, it has no timer left to send what was lost again
			recovery := tcpip.TCPRecovery(0)
			system.SetTransportProtocolOption(tcp.ProtocolNumber, &recovery)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				for {
					packet := endpoint.ReadContext(ctx)
					if packet == nil {
						return
					}
					var b []byte
					for _, part := range packet.AsSlices() {
						b = append(b, part...)
					}
					packet.DecRef()
					if !lost() {
						select {
						case l.in <- b:
						default:
							// as a tun does when its queue is full
						}
					}
				}
			}()
			l.out = func(b []byte) {
				if lost() {
					return
				}
				protocol := ipv4.ProtocolNumber
				if b[0]>>4 == 6 {
					protocol = ipv6.ProtocolNumber
				}
				packet := gstack.NewPacketBuffer(gstack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
				endpoint.InjectInbound(protocol, packet)
				packet.DecRef()
			}
			s := newTestStack(t, l, echo)

			for _, to := range []struct {
				address  tcpip.Address
				protocol tcpip.NetworkProtocolNumber
			}{
				{tcpip.AddrFrom4([4]byte{10, 0, 0, 2}), ipv4.ProtocolNumber},
				{tcpip.AddrFrom16([16]byte{0xfd, 15: 2}), ipv6.ProtocolNumber},
			} {
				conn, err := gonet.DialTCP(system, tcpip.FullAddress{NIC: 1, Addr: to.address, Port: 80}, to.protocol)
				if err != nil {
					t.Fatal(err)
				}
				sent := make([]byte, test.size)
				rand.Read(sent)
				go func() {
					conn.Write(sent)
					conn.CloseWrite()
				}()
				conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
				received, err := io.ReadAll(conn)
				if err != nil || !bytes.Equal(received, sent) {
					t.Fatal("received ", len(received), " of ", len(sent), " bytes, equal: ", bytes.Equal(received, sent), ", error: ", err)
				}
				conn.Close()
				forgotten(t, s)
			}
		})
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
}

func newPeer(t *testing.T, src, dst string) (*peer, *link) {
	l := newLink()
	p := &peer{t: t, l: l, sent: make(chan []byte, 1024), src: netip.MustParseAddrPort(src), dst: netip.MustParseAddrPort(dst), seq: 1000, window: 0xffff}
	l.out = func(b []byte) { p.sent <- b }
	return p, l
}

// send gives the stack a segment of the peer
func (p *peer) send(seq uint32, flags byte, options, payload []byte) {
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
	p.l.in <- append(b[:n+len(t):n+len(t)], payload...)
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
	b := p.packet()
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
