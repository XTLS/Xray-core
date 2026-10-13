package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type fragmentTestInput struct {
	packet []byte
	done   chan struct{}
}

// The next ReadPacket acknowledges that the preceding packet was processed.
type fragmentTestTun struct {
	in       chan fragmentTestInput
	done     chan struct{}
	readDone chan struct{}
	pending  chan struct{}
	once     sync.Once
}

func (f *fragmentTestTun) Start() error          { return nil }
func (f *fragmentTestTun) Name() (string, error) { return "fragment-test", nil }
func (f *fragmentTestTun) Index() (int, error)   { return 1, nil }
func (f *fragmentTestTun) Close() error {
	f.once.Do(func() { close(f.done) })
	return nil
}

func (f *fragmentTestTun) ReadPacket(b []byte) ([]byte, error) {
	if f.pending != nil {
		close(f.pending)
		f.pending = nil
	}
	select {
	case input := <-f.in:
		f.pending = input.done
		return b[packetRoom : packetRoom+copy(b[packetRoom:], input.packet)], nil
	case <-f.done:
		close(f.readDone)
		return nil, io.EOF
	}
}
func (f *fragmentTestTun) WritePacket(header, payload []byte) error { return nil }

func (f *fragmentTestTun) send(t *testing.T, packet []byte) {
	t.Helper()
	input := fragmentTestInput{packet: packet, done: make(chan struct{})}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case f.in <- input:
	case <-timer.C:
		t.Fatal("stack did not read an IP packet")
	}
	select {
	case <-input.done:
	case <-timer.C:
		t.Fatal("stack did not finish processing an IP packet")
	}
}

type fragmentTestDelivery struct {
	source, association, destination net.Destination
	hasDestination                   bool
	payload                          []byte
	err                              error
}

type fragmentTestFlow struct {
	closer io.Closer
	done   chan struct{}
}

// Keep each source association open and record every buffer until its reader closes.
type fragmentTestDispatcher struct {
	deliveries chan fragmentTestDelivery
	mu         sync.Mutex
	flows      []fragmentTestFlow
	stopping   bool
}

func (d *fragmentTestDispatcher) Type() interface{} { return routing.DispatcherType() }
func (d *fragmentTestDispatcher) Start() error      { return nil }
func (d *fragmentTestDispatcher) Close() error {
	d.mu.Lock()
	d.stopping = true
	flows := append([]fragmentTestFlow(nil), d.flows...)
	d.mu.Unlock()
	for _, flow := range flows {
		_ = flow.closer.Close()
	}
	for _, flow := range flows {
		select {
		case <-flow.done:
		case <-time.After(5 * time.Second):
			return fmt.Errorf("UDP dispatcher did not finish after closing its reader")
		}
	}
	return nil
}

func (d *fragmentTestDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	return nil, fmt.Errorf("test requires DispatchLink")
}

func (d *fragmentTestDispatcher) DispatchLink(ctx context.Context, destination net.Destination, link *transport.Link) error {
	reader, ok := link.Reader.(*buf.TimeoutWrapperReader)
	if !ok {
		return fmt.Errorf("unexpected TUN reader %T", link.Reader)
	}
	closer, ok := reader.Reader.(io.Closer)
	if !ok {
		return fmt.Errorf("TUN UDP reader %T cannot be closed", reader.Reader)
	}
	flow := fragmentTestFlow{closer: closer, done: make(chan struct{})}
	d.mu.Lock()
	if d.stopping {
		d.mu.Unlock()
		return closer.Close()
	}
	d.flows = append(d.flows, flow)
	d.mu.Unlock()
	defer close(flow.done)

	var source net.Destination
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		source = inbound.Source
	}
	for {
		mb, err := link.Reader.ReadMultiBuffer()
		for _, b := range mb {
			delivery := fragmentTestDelivery{
				source: source, association: destination, payload: bytes.Clone(b.Bytes()),
			}
			if b.UDP != nil {
				delivery.destination, delivery.hasDestination = *b.UDP, true
			}
			d.deliveries <- delivery
		}
		buf.ReleaseMulti(mb)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			d.deliveries <- fragmentTestDelivery{err: err}
			return err
		}
	}
}

func fragmentTestChecksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) != 0 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func fragmentTestTransportChecksum(src, dst netip.Addr, protocol byte, payload []byte) uint16 {
	var pseudo []byte
	if src.Is4() {
		pseudo = make([]byte, 12)
		s, d := src.As4(), dst.As4()
		copy(pseudo, s[:])
		copy(pseudo[4:], d[:])
		pseudo[9] = protocol
		binary.BigEndian.PutUint16(pseudo[10:], uint16(len(payload)))
	} else {
		pseudo = make([]byte, 40)
		s, d := src.As16(), dst.As16()
		copy(pseudo, s[:])
		copy(pseudo[16:], d[:])
		binary.BigEndian.PutUint32(pseudo[32:], uint32(len(payload)))
		pseudo[39] = protocol
	}
	return fragmentTestChecksum(append(pseudo, payload...))
}

func fragmentTestUDP(t *testing.T, src, dst netip.AddrPort, payload []byte) []byte {
	t.Helper()
	u := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(u, src.Port())
	binary.BigEndian.PutUint16(u[2:], dst.Port())
	binary.BigEndian.PutUint16(u[4:], uint16(len(u)))
	copy(u[8:], payload)
	check := fragmentTestTransportChecksum(src.Addr(), dst.Addr(), protoUDP, u)
	if check == 0 {
		check = 0xffff
	}
	binary.BigEndian.PutUint16(u[6:], check)
	if fragmentTestTransportChecksum(src.Addr(), dst.Addr(), protoUDP, u) != 0 {
		t.Fatal("invalid UDP fixture checksum")
	}
	return u
}

func fragmentTestIP(t *testing.T, src, dst netip.Addr, payload []byte, id uint32, offset int, more, fragmented bool) []byte {
	t.Helper()
	return fragmentTestIPProtocol(t, src, dst, payload, protoUDP, id, offset, more, fragmented)
}

func fragmentTestIPProtocol(t *testing.T, src, dst netip.Addr, payload []byte, protocol byte, id uint32, offset int, more, fragmented bool) []byte {
	t.Helper()
	if offset%8 != 0 || more && len(payload)%8 != 0 {
		t.Fatal("fragment fixture is not aligned to eight bytes")
	}
	var p []byte
	if src.Is4() {
		p = make([]byte, 20+len(payload))
		p[0], p[8], p[9] = 0x45, 64, protocol
		binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
		binary.BigEndian.PutUint16(p[4:], uint16(id))
		flags := uint16(offset / 8)
		if more {
			flags |= 0x2000
		}
		binary.BigEndian.PutUint16(p[6:], flags)
		s, d := src.As4(), dst.As4()
		copy(p[12:], s[:])
		copy(p[16:], d[:])
		binary.BigEndian.PutUint16(p[10:], fragmentTestChecksum(p[:20]))
		copy(p[20:], payload)
		if fragmentTestChecksum(p[:20]) != 0 {
			t.Fatal("invalid IPv4 fixture checksum")
		}
	} else {
		header := 40
		if fragmented {
			header += 8
		}
		p = make([]byte, header+len(payload))
		p[0], p[6], p[7] = 0x60, protocol, 64
		binary.BigEndian.PutUint16(p[4:], uint16(len(p)-40))
		s, d := src.As16(), dst.As16()
		copy(p[8:], s[:])
		copy(p[24:], d[:])
		if fragmented {
			p[6], p[40] = 44, protocol
			flags := uint16(offset)
			if more {
				flags |= 1
			}
			binary.BigEndian.PutUint16(p[42:], flags)
			binary.BigEndian.PutUint32(p[44:], id)
		}
		copy(p[header:], payload)
	}
	if len(p) > testMTU {
		t.Fatalf("IP fixture is larger than MTU: %d > %d", len(p), testMTU)
	}
	return p
}

// The unfragmentable Destination Options header points to Fragment; Fragment
// points to a second Destination Options header within the fragmentable data.
func fragmentTestIPv6Options(t *testing.T, p []byte) []byte {
	t.Helper()
	packet := make([]byte, len(p)+8)
	copy(packet, p[:40])
	copy(packet[40:48], []byte{44, 0, 1, 4, 0, 0, 0, 0}) // PadN
	copy(packet[48:], p[40:])
	packet[6], packet[48] = 60, 60
	binary.BigEndian.PutUint16(packet[4:], uint16(len(packet)-40))
	if len(packet) > testMTU {
		t.Fatal("IPv6 options fixture exceeds MTU")
	}
	return packet
}

func fragmentTestTake(t *testing.T, d *fragmentTestDispatcher, src, association, dst netip.AddrPort, payload []byte) {
	t.Helper()
	destination := func(address netip.AddrPort) net.Destination {
		return net.UDPDestination(net.IPAddress(address.Addr().AsSlice()), net.Port(address.Port()))
	}
	select {
	case got := <-d.deliveries:
		if got.err != nil || got.source != destination(src) || got.association != destination(association) ||
			!got.hasDestination || got.destination != destination(dst) || !bytes.Equal(got.payload, payload) {
			t.Fatalf("UDP delivery: source=%v association=%v destination=%v present=%v bytes=%d err=%v; want %v -> %v (%v), bytes=%d",
				got.source, got.association, got.destination, got.hasDestination, len(got.payload), got.err,
				src, dst, association, len(payload))
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("no UDP delivery from %v to %v with %d bytes", src, dst, len(payload))
	}
}

// Valid IP fragments must become complete datagrams on the native UDP link.
func TestUDPIPFragments(t *testing.T) {
	for _, addresses := range []struct {
		name, src, dst string
		options        bool
	}{
		{"IPv4", "10.0.0.1:12340", "10.0.0.2:5353", false},
		{"IPv6", "[fd00::1]:12340", "[fd00::2]:5353", false},
		{"IPv6-options", "[fd00::1]:12340", "[fd00::2]:5353", true},
	} {
		for _, reverse := range []bool{false, true} {
			order := "in-order"
			if reverse {
				order = "reverse-order"
			}
			t.Run(addresses.name+"/"+order, func(t *testing.T) {
				src, association := netip.MustParseAddrPort(addresses.src), netip.MustParseAddrPort(addresses.dst)
				device := &fragmentTestTun{in: make(chan fragmentTestInput), done: make(chan struct{}), readDone: make(chan struct{})}
				dispatcher := &fragmentTestDispatcher{deliveries: make(chan fragmentTestDelivery, 64)}
				handler := &Handler{ctx: context.Background(), config: &Config{}, dispatcher: dispatcher}
				stack, err := NewStack(context.Background(), StackOptions{Tun: device, MTU: testMTU}, handler)
				if err != nil {
					t.Fatal(err)
				}
				if err := stack.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					_ = stack.Close()
					_ = device.Close()
					select {
					case <-device.readDone:
					case <-time.After(5 * time.Second):
						t.Error("stack did not stop reading its TUN")
					}
					if err := dispatcher.Close(); err != nil {
						t.Error(err)
					}
				})
				sendControl := func(payload []byte) {
					u := fragmentTestUDP(t, src, association, payload)
					device.send(t, fragmentTestIP(t, src.Addr(), association.Addr(), u, 0, 0, false, false))
					fragmentTestTake(t, dispatcher, src, association, association, payload)
				}

				// Establish a persistent flow through NewStack, Handler and DispatchLink.
				sendControl([]byte("unfragmented positive control"))
				for datagram := 0; datagram < 2; datagram++ {
					dst := netip.AddrPortFrom(association.Addr(), association.Port()+uint16(datagram)+1)
					payload := make([]byte, 1600)
					for i := range payload {
						payload[i] = byte(i + datagram)
					}
					u := fragmentTestUDP(t, src, dst, payload)
					if addresses.options {
						u = append([]byte{protoUDP, 0, 1, 4, 0, 0, 0, 0}, u...)
					}
					const split = 1224
					id := uint32(100 + datagram)
					fragments := [][]byte{
						fragmentTestIP(t, src.Addr(), dst.Addr(), u[:split], id, 0, true, true),
						fragmentTestIP(t, src.Addr(), dst.Addr(), u[split:], id, split, false, true),
					}
					if addresses.options {
						for i := range fragments {
							fragments[i] = fragmentTestIPv6Options(t, fragments[i])
						}
					}
					if reverse {
						fragments[0], fragments[1] = fragments[1], fragments[0]
					}
					device.send(t, fragments[0])
					device.send(t, fragments[0]) // identical duplicate before completion
					// A same-flow control is queued after both incomplete fragments. It must
					// be the next buffer: there is no sleep-based absence assertion.
					sendControl([]byte(fmt.Sprintf("incomplete fragment barrier %d", datagram)))
					device.send(t, fragments[1])
					fragmentTestTake(t, dispatcher, src, association, dst, payload)
					// The next control must follow exactly one complete datagram.
					sendControl([]byte(fmt.Sprintf("complete datagram barrier %d", datagram)))
				}
				dispatcher.mu.Lock()
				flows := len(dispatcher.flows)
				dispatcher.mu.Unlock()
				if flows != 1 {
					t.Fatalf("same UDP source opened %d associations, want 1", flows)
				}
			})
		}
	}
}

func fragmentTestTCPRead(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	mb, err := conn.(buf.Reader).ReadMultiBuffer()
	defer buf.ReleaseMulti(mb)
	if err != nil || mb.String() != string(payload) {
		t.Fatalf("TCP read %d bytes, want %d, error %v", mb.Len(), len(payload), err)
	}
}

func TestTCPIPFragments(t *testing.T) {
	for _, addresses := range []struct{ name, src, dst string }{
		{"IPv4", "10.0.0.1:12340", "10.0.0.2:80"},
		{"IPv6", "[fd00::1]:12340", "[fd00::2]:80"},
	} {
		for _, reverse := range []bool{false, true} {
			order := "in-order"
			if reverse {
				order = "reverse-order"
			}
			t.Run(addresses.name+"/"+order, func(t *testing.T) {
				conns := make(chan accepted, 1)
				p, l := newPeer(t, addresses.src, addresses.dst)
				newTestStack(t, l, accept(conns))
				p.connect(nil)
				a := take(t, conns)
				t.Cleanup(func() { _ = a.conn.Close() })
				if a.conn.RemoteAddr().String() != addresses.src ||
					a.dest != net.TCPDestination(net.IPAddress(p.dst.Addr().AsSlice()), net.Port(p.dst.Port())) {
					t.Fatalf("TCP association from %v to %v", a.conn.RemoteAddr(), a.dest)
				}

				control := "unfragmented TCP control"
				p.send(p.seq, tcpAck|tcpPsh, nil, []byte(control))
				p.seq += uint32(len(control))
				if ack := p.receive(); ack.ack != p.seq {
					t.Fatalf("control ACK = %d, want %d", ack.ack, p.seq)
				}
				fragmentTestTCPRead(t, a.conn, []byte(control))

				payload := make([]byte, 1600)
				for i := range payload {
					payload[i] = byte(i)
				}
				segment := make([]byte, tcpHeaderSize+len(payload))
				binary.BigEndian.PutUint16(segment, p.src.Port())
				binary.BigEndian.PutUint16(segment[2:], p.dst.Port())
				binary.BigEndian.PutUint32(segment[4:], p.seq)
				binary.BigEndian.PutUint32(segment[8:], p.ack)
				segment[12], segment[13] = 5<<4, tcpAck|tcpPsh
				binary.BigEndian.PutUint16(segment[14:], p.window)
				copy(segment[tcpHeaderSize:], payload)
				binary.BigEndian.PutUint16(segment[16:], fragmentTestTransportChecksum(p.src.Addr(), p.dst.Addr(), protoTCP, segment))
				if fragmentTestTransportChecksum(p.src.Addr(), p.dst.Addr(), protoTCP, segment) != 0 {
					t.Fatal("invalid TCP fixture checksum")
				}
				const split = 1224
				fragments := [][]byte{
					fragmentTestIPProtocol(t, p.src.Addr(), p.dst.Addr(), segment[:split], protoTCP, 200, 0, true, true),
					fragmentTestIPProtocol(t, p.src.Addr(), p.dst.Addr(), segment[split:], protoTCP, 200, split, false, true),
				}
				if reverse {
					fragments[0], fragments[1] = fragments[1], fragments[0]
				}
				for _, fragment := range fragments {
					l.in <- fragment
				}
				p.seq += uint32(len(payload))
				// A full ACK bounds the wait and confirms that the established TCP
				// connection accepted the entire reassembled segment before reading.
				if ack := p.receive(); ack.ack != p.seq {
					t.Fatalf("fragmented TCP ACK = %d, want %d", ack.ack, p.seq)
				}
				fragmentTestTCPRead(t, a.conn, payload)
			})
		}
	}
}

func fragmentTestEcho(t *testing.T, src, dst netip.Addr, payload []byte) []byte {
	t.Helper()
	m := make([]byte, 8+len(payload))
	m[0] = 8
	if src.Is6() {
		m[0] = 128
	}
	binary.BigEndian.PutUint16(m[4:], 0x1234)
	binary.BigEndian.PutUint16(m[6:], 0x5678)
	copy(m[8:], payload)
	check := fragmentTestChecksum(m)
	if src.Is6() {
		check = fragmentTestTransportChecksum(src, dst, protoICMPv6, m)
	}
	binary.BigEndian.PutUint16(m[2:], check)
	check = fragmentTestChecksum(m)
	if src.Is6() {
		check = fragmentTestTransportChecksum(src, dst, protoICMPv6, m)
	}
	if check != 0 {
		t.Fatal("invalid ICMP echo fixture checksum")
	}
	return m
}

func fragmentTestEchoReply(t *testing.T, packet []byte, src, dst netip.Addr, request []byte) {
	t.Helper()
	protocol, headerSize, reply := byte(protoICMPv4), ipv4HeaderSize, byte(0)
	if src.Is6() {
		protocol, headerSize, reply = protoICMPv6, ipv6HeaderSize, 129
	}
	if len(packet) != headerSize+len(request) {
		t.Fatalf("echo reply has %d bytes, want %d", len(packet), headerSize+len(request))
	}
	if src.Is4() && fragmentTestChecksum(packet[:headerSize]) != 0 {
		t.Fatal("invalid echo reply IPv4 header checksum")
	}
	p, ok := parsePacket(packet)
	if !ok || p.proto != protocol || p.src != dst || p.dst != src {
		t.Fatalf("echo reply from %v to %v protocol %d, want %v -> %v protocol %d", p.src, p.dst, p.proto, dst, src, protocol)
	}
	want := bytes.Clone(request)
	want[0], want[2], want[3] = reply, 0, 0
	check := fragmentTestChecksum(want)
	if src.Is6() {
		check = fragmentTestTransportChecksum(dst, src, protoICMPv6, want)
	}
	binary.BigEndian.PutUint16(want[2:], check)
	if !bytes.Equal(p.payload, want) {
		t.Fatal("echo reply changed its identifier, sequence, payload or checksum")
	}
}

func TestICMPIPFragments(t *testing.T) {
	for _, addresses := range []struct{ name, src, dst string }{
		{"IPv4", "10.0.0.1:1", "10.0.0.2:1"},
		{"IPv6", "[fd00::1]:1", "[fd00::2]:1"},
	} {
		for _, reverse := range []bool{false, true} {
			order := "in-order"
			if reverse {
				order = "reverse-order"
			}
			t.Run(addresses.name+"/"+order, func(t *testing.T) {
				p, l := newPeer(t, addresses.src, addresses.dst)
				newTestStack(t, l, func(conn net.Conn, dest net.Destination) {
					_ = conn.Close()
					t.Errorf("ICMP unexpectedly opened a connection to %v", dest)
				})
				src, dst := p.src.Addr(), p.dst.Addr()
				protocol := byte(protoICMPv4)
				if src.Is6() {
					protocol = protoICMPv6
				}
				control := fragmentTestEcho(t, src, dst, []byte("unfragmented echo control"))
				l.in <- fragmentTestIPProtocol(t, src, dst, control, protocol, 0, 0, false, false)
				fragmentTestEchoReply(t, p.packet(), src, dst, control)

				payload := make([]byte, 1600)
				for i := range payload {
					payload[i] = byte(i)
				}
				request := fragmentTestEcho(t, src, dst, payload)
				const split = 1224
				fragments := [][]byte{
					fragmentTestIPProtocol(t, src, dst, request[:split], protocol, 300, 0, true, true),
					fragmentTestIPProtocol(t, src, dst, request[split:], protocol, 300, split, false, true),
				}
				if reverse {
					fragments[0], fragments[1] = fragments[1], fragments[0]
				}
				for _, fragment := range fragments {
					l.in <- fragment
				}
				fragmentTestEchoReply(t, p.packet(), src, dst, request)
			})
		}
	}
}
