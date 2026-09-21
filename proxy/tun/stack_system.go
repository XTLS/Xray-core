package tun

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	xerrors "github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	tunicmp "github.com/xtls/xray-core/proxy/tun/icmp"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// stackSystem is the lightweight, Xray-native ip stack, see NewStack.
//
// It reads and parses IPv4/IPv6 packets directly off the tun device (through
// the GVisorDevice interface, already implemented for every supported
// platform), without involving gVisor's stack.Stack, NIC or routing
// machinery. UDP and ICMP echo reuse the exact same handlers as the gVisor
// backend (udpConnectionHandler, tun/icmp) since those were already
// implemented in terms of raw bytes. TCP is handled by a small dedicated
// state machine, see stack_system_tcp.go.
type stackSystem struct {
	ctx         context.Context
	device      GVisorDevice
	mtu         uint32
	idleTimeout time.Duration
	handler     *Handler

	udp *udpConnectionHandler

	tcpMu sync.Mutex
	tcp   map[tcpKey]*tcpConn

	cancel context.CancelFunc
}

const systemStackDefaultMTU = 1500

// newSystemStack builds the lightweight "system" ip stack, see NewStack.
func newSystemStack(ctx context.Context, options StackOptions, handler *Handler) (Stack, error) {
	device, ok := options.Tun.(GVisorDevice)
	if !ok {
		return nil, xerrors.New("tun stack \"system\" is not supported by this tun device")
	}
	mtu := options.MTU
	if mtu == 0 {
		mtu = systemStackDefaultMTU
	}
	return &stackSystem{
		ctx:         ctx,
		device:      device,
		mtu:         mtu,
		idleTimeout: options.IdleTimeout,
		handler:     handler,
		tcp:         make(map[tcpKey]*tcpConn),
	}, nil
}

// Start is called by Handler to bring the stack to life
func (s *stackSystem) Start() error {
	ctx, cancel := context.WithCancel(s.ctx)
	s.cancel = cancel
	s.udp = newUdpConnectionHandler(s.handler.HandleConnection, s.writeRawUDPPacket)

	go s.dispatchLoop(ctx)
	go s.idleReapLoop(ctx)
	return nil
}

// Close is called by Handler to shut down the stack
func (s *stackSystem) Close() error {
	if s.cancel != nil {
		s.cancel()
	}

	s.tcpMu.Lock()
	conns := make([]*tcpConn, 0, len(s.tcp))
	for _, c := range s.tcp {
		conns = append(conns, c)
	}
	s.tcp = make(map[tcpKey]*tcpConn)
	s.tcpMu.Unlock()

	for _, c := range conns {
		c.abort(errStackClosed)
	}

	return nil
}

// dispatchLoop reads and demultiplexes packets off the tun device, until ctx
// is cancelled or the device fails permanently. It mirrors LinkEndpoint's own
// dispatchLoop (stack_gvisor_endpoint.go), reusing the exact same GVisorDevice
// contract, but hands packets to this file's own IPv4/IPv6 parsing instead of
// gVisor's NIC/stack.Stack.
func (s *stackSystem) dispatchLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		version, packet, err := s.device.ReadPacket()
		if err != nil {
			if errors.Is(err, ErrQueueEmpty) {
				s.device.Wait()
				continue
			}
			return
		}

		s.handlePacket(version, packet)
		packet.DecRef()
	}
}

func (s *stackSystem) handlePacket(version byte, packet *stack.PacketBuffer) {
	data := concatSlices(packet.AsSlices())
	if len(data) == 0 {
		return
	}

	switch version {
	case 4:
		s.handleIPv4(data)
	case 6:
		s.handleIPv6(data)
	}
}

func concatSlices(slices [][]byte) []byte {
	if len(slices) == 1 {
		return slices[0]
	}
	total := 0
	for _, sl := range slices {
		total += len(sl)
	}
	if total == 0 {
		return nil
	}
	data := make([]byte, 0, total)
	for _, sl := range slices {
		data = append(data, sl...)
	}
	return data
}

func (s *stackSystem) handleIPv4(data []byte) {
	hdr := header.IPv4(data)
	if !hdr.IsValid(len(data)) {
		return
	}
	// fragmentation is not supported: the tun MTU is expected to keep locally
	// generated packets from ever needing it, same as the gVisor backend's
	// default configuration
	if hdr.More() || hdr.FragmentOffset() != 0 {
		return
	}

	s.handleTransport(header.IPv4ProtocolNumber, hdr.TransportProtocol(), hdr.SourceAddress(), hdr.DestinationAddress(), hdr.Payload())
}

func (s *stackSystem) handleIPv6(data []byte) {
	hdr := header.IPv6(data)
	if !hdr.IsValid(len(data)) {
		return
	}

	// only directly-encapsulated transport headers are handled, IPv6
	// extension headers (rare for ordinary locally generated traffic) are not
	// walked, same limitation as the fragmentation one above
	s.handleTransport(header.IPv6ProtocolNumber, hdr.TransportProtocol(), hdr.SourceAddress(), hdr.DestinationAddress(), hdr.Payload())
}

func (s *stackSystem) handleTransport(netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, srcIP, dstIP tcpip.Address, payload []byte) {
	switch transProto {
	case header.TCPProtocolNumber:
		s.handleTCP(netProto, srcIP, dstIP, payload)
	case header.UDPProtocolNumber:
		s.handleUDP(netProto, srcIP, dstIP, payload)
	case header.ICMPv4ProtocolNumber:
		if netProto == header.IPv4ProtocolNumber {
			s.handleICMP(netProto, srcIP, dstIP, payload)
		}
	case header.ICMPv6ProtocolNumber:
		if netProto == header.IPv6ProtocolNumber {
			s.handleICMP(netProto, srcIP, dstIP, payload)
		}
	}
}

func (s *stackSystem) handleUDP(netProto tcpip.NetworkProtocolNumber, srcIP, dstIP tcpip.Address, payload []byte) {
	if len(payload) < header.UDPMinimumSize {
		return
	}
	udpHdr := header.UDP(payload)
	length := udpHdr.Length()
	if int(length) < header.UDPMinimumSize || int(length) > len(payload) {
		return
	}

	// source/destination of the packet we process as incoming are, in other terms,
	// src is the side behind tun, dst is the side behind the dispatcher
	src := net.UDPDestination(net.IPAddress(srcIP.AsSlice()), net.Port(udpHdr.SourcePort()))
	dst := net.UDPDestination(net.IPAddress(dstIP.AsSlice()), net.Port(udpHdr.DestinationPort()))
	s.udp.HandlePacket(src, dst, payload[header.UDPMinimumSize:length])
}

func (s *stackSystem) handleICMP(netProto tcpip.NetworkProtocolNumber, srcIP, dstIP tcpip.Address, message []byte) {
	ident, sequence, ok := tunicmp.ParseEchoRequest(netProto, message)
	if !ok {
		return
	}

	reply, err := tunicmp.BuildLocalEchoReply(netProto, message, dstIP, srcIP)
	if err != nil {
		xerrors.LogInfoInner(s.ctx, err, "[tun] failed to build local icmp echo reply")
		return
	}

	xerrors.LogDebug(s.ctx, "[tun][icmp] ", tunicmp.ProtocolLabel(netProto), " local echo reply ", dstIP, " -> ", srcIP, " id=", ident, " seq=", sequence)

	transProto := header.ICMPv4ProtocolNumber
	if netProto == header.IPv6ProtocolNumber {
		transProto = header.ICMPv6ProtocolNumber
	}
	if err := s.writeTransportSegment(netProto, tcpip.TransportProtocolNumber(transProto), dstIP, srcIP, reply); err != nil {
		xerrors.LogInfoInner(s.ctx, err, "[tun] failed to write local icmp echo reply")
	}
}

func (s *stackSystem) writeRawUDPPacket(payload []byte, src net.Destination, dst net.Destination) error {
	udpLen := header.UDPMinimumSize + len(payload)
	srcIP := tcpip.AddrFromSlice(src.Address.IP())
	dstIP := tcpip.AddrFromSlice(dst.Address.IP())

	netProto := header.IPv4ProtocolNumber
	if !dst.Address.Family().IsIPv4() {
		netProto = header.IPv6ProtocolNumber
	}

	segment := make([]byte, udpLen)
	udpHdr := header.UDP(segment)
	udpHdr.Encode(&header.UDPFields{
		SrcPort: uint16(src.Port),
		DstPort: uint16(dst.Port),
		Length:  uint16(udpLen),
	})
	copy(segment[header.UDPMinimumSize:], payload)

	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, srcIP, dstIP, uint16(udpLen))
	udpHdr.SetChecksum(^udpHdr.CalculateChecksum(checksum.Checksum(payload, xsum)))

	return s.writeTransportSegment(netProto, header.UDPProtocolNumber, srcIP, dstIP, segment)
}

// writeTransportSegment wraps a fully built, already checksummed transport
// layer segment (UDP, ICMP or TCP) with an IP header and writes it to the tun
// device.
func (s *stackSystem) writeTransportSegment(netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, srcIP, dstIP tcpip.Address, segment []byte) error {
	ipHdrSize := header.IPv4MinimumSize
	if netProto == header.IPv6ProtocolNumber {
		ipHdrSize = header.IPv6MinimumSize
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: ipHdrSize,
		Payload:            buffer.MakeWithData(segment),
	})
	defer pkt.DecRef()

	if netProto == header.IPv4ProtocolNumber {
		ipHdr := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
		ipHdr.Encode(&header.IPv4Fields{
			TotalLength: uint16(header.IPv4MinimumSize + len(segment)),
			TTL:         64,
			Protocol:    uint8(transProto),
			SrcAddr:     srcIP,
			DstAddr:     dstIP,
		})
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	} else {
		ipHdr := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
		ipHdr.Encode(&header.IPv6Fields{
			PayloadLength:     uint16(len(segment)),
			TransportProtocol: transProto,
			HopLimit:          64,
			SrcAddr:           srcIP,
			DstAddr:           dstIP,
		})
	}

	if err := s.device.WritePacket(pkt); err != nil {
		return xerrors.New("failed to write raw packet: ", err.String())
	}
	return nil
}

// idleReapLoop periodically aborts tcp connections that have seen no traffic
// for longer than idleTimeout, finally putting that option to use (it was
// tracked but never read anywhere before the "system" backend existed).
func (s *stackSystem) idleReapLoop(ctx context.Context) {
	if s.idleTimeout <= 0 {
		return
	}
	interval := s.idleTimeout / 4
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reapIdleConnections()
		}
	}
}

func (s *stackSystem) reapIdleConnections() {
	deadline := time.Now().Add(-s.idleTimeout)

	s.tcpMu.Lock()
	var idle []*tcpConn
	for _, c := range s.tcp {
		if c.lastActiveTime().Before(deadline) {
			idle = append(idle, c)
		}
	}
	s.tcpMu.Unlock()

	for _, c := range idle {
		c.abort(errConnIdleTimeout)
	}
}

func (s *stackSystem) removeTCPConn(key tcpKey, c *tcpConn) {
	s.tcpMu.Lock()
	if existing, ok := s.tcp[key]; ok && existing == c {
		delete(s.tcp, key)
	}
	s.tcpMu.Unlock()
}

// randomSequenceNumber returns a random initial sequence number for a new
// connection. It doesn't need to be cryptographically unpredictable (the tun
// channel is local and trusted), just varied enough to avoid confusion with
// prior incarnations of the same 4-tuple.
func randomSequenceNumber() seqnum.Value {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return seqnum.Value(binary.BigEndian.Uint32(b[:]))
}
