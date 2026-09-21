package tun

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// fakeGVisorDevice is an in-memory GVisorDevice used to script conversations
// with the "system" stack without any real tun device or privileges.
type fakeGVisorDevice struct {
	inbound  chan []byte
	outbound chan []byte
	notify   chan struct{}
}

func newFakeGVisorDevice() *fakeGVisorDevice {
	return &fakeGVisorDevice{
		inbound:  make(chan []byte, 256),
		outbound: make(chan []byte, 256),
		notify:   make(chan struct{}, 1),
	}
}

func (d *fakeGVisorDevice) push(data []byte) {
	d.inbound <- data
	select {
	case d.notify <- struct{}{}:
	default:
	}
}

func (d *fakeGVisorDevice) ReadPacket() (byte, *stack.PacketBuffer, error) {
	select {
	case data := <-d.inbound:
		version := data[0] >> 4
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
		return version, pkt, nil
	default:
		return 0, nil, ErrQueueEmpty
	}
}

func (d *fakeGVisorDevice) WritePacket(packet *stack.PacketBuffer) tcpip.Error {
	var data []byte
	for _, s := range packet.AsSlices() {
		data = append(data, s...)
	}
	d.outbound <- data
	return nil
}

func (d *fakeGVisorDevice) Wait() {
	select {
	case <-d.notify:
	case <-time.After(20 * time.Millisecond):
	}
}

func (d *fakeGVisorDevice) recv(t *testing.T, timeout time.Duration) []byte {
	t.Helper()
	select {
	case data := <-d.outbound:
		return data
	case <-time.After(timeout):
		t.Fatal("timed out waiting for outbound packet")
		return nil
	}
}

var _ GVisorDevice = (*fakeGVisorDevice)(nil)

// echoHandler is a ConnectionHandler that echoes back everything it reads on
// each connection, and records connections/destinations it has seen.
type echoHandler struct {
	mu    sync.Mutex
	conns []net.Conn
	dests []net.Destination
	done  chan struct{}
}

func newEchoHandler() *echoHandler {
	return &echoHandler{done: make(chan struct{}, 8)}
}

func (h *echoHandler) HandleConnection(conn net.Conn, dest net.Destination) {
	h.mu.Lock()
	h.conns = append(h.conns, conn)
	h.dests = append(h.dests, dest)
	h.mu.Unlock()

	_, _ = io.Copy(conn, conn)
	_ = conn.Close()
	h.done <- struct{}{}
}

func newTestStackSystem(device GVisorDevice, handler ConnectionHandler, idleTimeout time.Duration) (*stackSystem, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &stackSystem{
		ctx:         ctx,
		device:      device,
		mtu:         1500,
		idleTimeout: idleTimeout,
		handler:     handler,
		tcp:         make(map[tcpKey]*tcpConn),
	}
	return s, cancel
}

func testIP(s string) tcpip.Address {
	return tcpip.AddrFrom4Slice(net.ParseIP(s).To4())
}

const (
	testPeerIP   = "10.0.0.2"
	testTargetIP = "10.0.0.1"
	testPeerPort = uint16(51234)
	testDstPort  = uint16(8080)
)

// buildIPv4TCP builds a raw IPv4+TCP segment, computing valid checksums.
func buildIPv4TCP(src, dst tcpip.Address, srcPort, dstPort uint16, seq, ack uint32, flags header.TCPFlags, window uint16, payload []byte, options []byte) []byte {
	headerLen := header.TCPMinimumSize + len(options)
	totalLen := header.IPv4MinimumSize + headerLen + len(payload)
	data := make([]byte, totalLen)

	ipHdr := header.IPv4(data)
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())

	tcpHdr := header.TCP(data[header.IPv4MinimumSize:])
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     seq,
		AckNum:     ack,
		DataOffset: uint8(headerLen),
		Flags:      flags,
		WindowSize: window,
	})
	copy(tcpHdr.Options(), options)
	copy(data[header.IPv4MinimumSize+headerLen:], payload)

	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, src, dst, uint16(headerLen+len(payload)))
	xsum = checksum.Checksum(payload, xsum)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(xsum))

	return data
}

func parseIPv4TCP(t *testing.T, data []byte) header.TCP {
	t.Helper()
	ipHdr := header.IPv4(data)
	if !ipHdr.IsValid(len(data)) {
		t.Fatalf("invalid ipv4 packet")
	}
	return header.TCP(ipHdr.Payload())
}

func TestSystemStackTCPHandshakeEchoClose(t *testing.T) {
	device := newFakeGVisorDevice()
	handler := newEchoHandler()
	s, cancel := newTestStackSystem(device, handler, time.Minute)
	defer cancel()
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Close()

	src := testIP(testPeerIP)
	dst := testIP(testTargetIP)

	iss := uint32(1000)
	device.push(buildIPv4TCP(src, dst, testPeerPort, testDstPort, iss, 0, header.TCPFlagSyn, 65535, nil, nil))

	synAck := parseIPv4TCP(t, device.recv(t, time.Second))
	if synAck.Flags() != header.TCPFlagSyn|header.TCPFlagAck {
		t.Fatalf("expected SYN-ACK, got flags %v", synAck.Flags())
	}
	if synAck.AckNumber() != iss+1 {
		t.Fatalf("unexpected ack number %d, want %d", synAck.AckNumber(), iss+1)
	}
	serverISS := synAck.SequenceNumber()

	// final handshake ACK
	device.push(buildIPv4TCP(src, dst, testPeerPort, testDstPort, iss+1, serverISS+1, header.TCPFlagAck, 65535, nil, nil))

	// send data
	payload := []byte("hello world")
	device.push(buildIPv4TCP(src, dst, testPeerPort, testDstPort, iss+1, serverISS+1, header.TCPFlagAck|header.TCPFlagPsh, 65535, payload, nil))

	// drain outbound packets until the full echo has been observed, acking
	// any data segments as they arrive so the connection can make progress
	var echoed []byte
	deadline := time.After(2 * time.Second)
	for len(echoed) < len(payload) {
		select {
		case raw := <-device.outbound:
			tcpHdr := parseIPv4TCP(t, raw)
			if len(tcpHdr.Payload()) > 0 {
				echoed = append(echoed, tcpHdr.Payload()...)
				device.push(buildIPv4TCP(src, dst, testPeerPort, testDstPort,
					iss+1+uint32(len(payload)), tcpHdr.SequenceNumber()+uint32(len(tcpHdr.Payload())),
					header.TCPFlagAck, 65535, nil, nil))
			}
		case <-deadline:
			t.Fatalf("timed out waiting for echo, got %q so far", echoed)
		}
	}
	if string(echoed) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", echoed, payload)
	}

	h := handler
	h.mu.Lock()
	if len(h.dests) != 1 || h.dests[0].NetAddr() != "10.0.0.1:8080" {
		t.Fatalf("unexpected destination recorded: %+v", h.dests)
	}
	h.mu.Unlock()

	// peer sends FIN
	finSeq := iss + 1 + uint32(len(payload))
	device.push(buildIPv4TCP(src, dst, testPeerPort, testDstPort, finSeq, serverISS+1+uint32(len(payload)), header.TCPFlagFin|header.TCPFlagAck, 65535, nil, nil))

	select {
	case <-handler.done:
	case <-time.After(2 * time.Second):
		t.Fatal("echo handler never finished after peer FIN")
	}

	var sawAckOfFin, sawOurFin bool
	var ourFinSeq uint32
	deadline = time.After(2 * time.Second)
	for !sawAckOfFin || !sawOurFin {
		select {
		case raw := <-device.outbound:
			tcpHdr := parseIPv4TCP(t, raw)
			if tcpHdr.Flags()&header.TCPFlagFin != 0 {
				sawOurFin = true
				ourFinSeq = tcpHdr.SequenceNumber()
			}
			if tcpHdr.AckNumber() == finSeq+1 {
				sawAckOfFin = true
			}
		case <-deadline:
			t.Fatalf("timed out waiting for our fin/ack (sawAckOfFin=%v sawOurFin=%v)", sawAckOfFin, sawOurFin)
		}
	}

	// ack our FIN, completing a graceful close
	device.push(buildIPv4TCP(src, dst, testPeerPort, testDstPort, finSeq+1, ourFinSeq+1, header.TCPFlagAck, 65535, nil, nil))

	deadline = time.After(2 * time.Second)
	for {
		s.tcpMu.Lock()
		var conn *tcpConn
		for _, c := range s.tcp {
			conn = c
		}
		s.tcpMu.Unlock()
		if conn == nil {
			t.Fatal("connection unexpectedly removed before linger")
		}
		conn.mu.Lock()
		state := conn.state
		conn.mu.Unlock()
		if state == stateTimeWait {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("connection did not reach TimeWait, state=%d", state)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestSystemStackTCPUnknownConnectionReset(t *testing.T) {
	device := newFakeGVisorDevice()
	handler := newEchoHandler()
	s, cancel := newTestStackSystem(device, handler, time.Minute)
	defer cancel()
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Close()

	src := testIP(testPeerIP)
	dst := testIP(testTargetIP)

	// an ACK referencing a connection the stack has never seen
	device.push(buildIPv4TCP(src, dst, testPeerPort, testDstPort, 5000, 0, header.TCPFlagAck, 65535, nil, nil))

	rst := parseIPv4TCP(t, device.recv(t, time.Second))
	if rst.Flags()&header.TCPFlagRst == 0 {
		t.Fatalf("expected RST, got flags %v", rst.Flags())
	}
	if rst.SequenceNumber() != 5000 {
		t.Fatalf("expected reset seq to echo the ack number 5000, got %d", rst.SequenceNumber())
	}
}

func TestSystemStackTCPRetransmit(t *testing.T) {
	device := newFakeGVisorDevice()
	handler := newEchoHandler()
	s, cancel := newTestStackSystem(device, handler, time.Minute)
	defer cancel()
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Close()

	src := testIP(testPeerIP)
	dst := testIP(testTargetIP)

	iss := uint32(2000)
	device.push(buildIPv4TCP(src, dst, testPeerPort, testDstPort, iss, 0, header.TCPFlagSyn, 65535, nil, nil))
	synAck := parseIPv4TCP(t, device.recv(t, time.Second))
	serverISS := synAck.SequenceNumber()
	device.push(buildIPv4TCP(src, dst, testPeerPort, testDstPort, iss+1, serverISS+1, header.TCPFlagAck, 65535, nil, nil))

	payload := []byte("hi")
	device.push(buildIPv4TCP(src, dst, testPeerPort, testDstPort, iss+1, serverISS+1, header.TCPFlagAck|header.TCPFlagPsh, 65535, payload, nil))

	// consume the data-ack and the first echoed data segment, but do NOT ack
	// the echoed data, forcing a retransmit
	var first []byte
	deadline := time.After(2 * time.Second)
	for len(first) == 0 {
		select {
		case raw := <-device.outbound:
			tcpHdr := parseIPv4TCP(t, raw)
			if len(tcpHdr.Payload()) > 0 {
				first = append([]byte(nil), tcpHdr.Payload()...)
			}
		case <-deadline:
			t.Fatal("timed out waiting for first echoed segment")
		}
	}

	// now wait for a retransmission of the same bytes, without acking
	deadline = time.After(2 * time.Second)
	for {
		select {
		case raw := <-device.outbound:
			tcpHdr := parseIPv4TCP(t, raw)
			if string(tcpHdr.Payload()) == string(first) {
				return // retransmit observed, test passes
			}
		case <-deadline:
			t.Fatal("timed out waiting for retransmission of unacked data")
		}
	}
}

func TestSystemStackIdleReap(t *testing.T) {
	device := newFakeGVisorDevice()
	handler := newEchoHandler()
	s, cancel := newTestStackSystem(device, handler, time.Millisecond)
	defer cancel()
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Close()

	src := testIP(testPeerIP)
	dst := testIP(testTargetIP)

	device.push(buildIPv4TCP(src, dst, testPeerPort, testDstPort, 1, 0, header.TCPFlagSyn, 65535, nil, nil))
	device.recv(t, time.Second) // SYN-ACK

	deadline := time.After(2 * time.Second)
	for {
		s.tcpMu.Lock()
		n := len(s.tcp)
		s.tcpMu.Unlock()
		if n == 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatal("idle connection was not reaped")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestSystemStackUDPEcho(t *testing.T) {
	device := newFakeGVisorDevice()
	handler := newEchoHandler()
	s, cancel := newTestStackSystem(device, handler, time.Minute)
	defer cancel()
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Close()

	src := testIP(testPeerIP)
	dst := testIP(testTargetIP)

	payload := []byte("ping")
	udpLen := header.UDPMinimumSize + len(payload)
	totalLen := header.IPv4MinimumSize + udpLen
	data := make([]byte, totalLen)
	ipHdr := header.IPv4(data)
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	udpHdr := header.UDP(data[header.IPv4MinimumSize:])
	udpHdr.Encode(&header.UDPFields{SrcPort: testPeerPort, DstPort: testDstPort, Length: uint16(udpLen)})
	copy(data[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, src, dst, uint16(udpLen))
	udpHdr.SetChecksum(^udpHdr.CalculateChecksum(checksum.Checksum(payload, xsum)))

	device.push(data)

	select {
	case <-handler.done:
	case <-time.After(time.Second):
		t.Fatal("udp handler never invoked/finished")
	}

	handler.mu.Lock()
	defer handler.mu.Unlock()
	if len(handler.dests) != 1 || handler.dests[0].Network != net.Network_UDP {
		t.Fatalf("unexpected udp destination recorded: %+v", handler.dests)
	}
}
