package tun

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

type SystemStack struct {
	ctx         context.Context
	tun         Tun
	handler     StackHandler
	mtu         int
	tunAddr4    netip.Addr
	tunAddr6    netip.Addr
	natAddr4    netip.Addr
	natAddr6    netip.Addr
	dstAddr4    netip.Addr
	dstAddr6    netip.Addr
	tcpNAT      *TCPNAT
	udpNAT      *UDPNAT
	udpTimeout  time.Duration
	icmpTimeout time.Duration
	strictRoute bool

	dnsHijacker *DNSHijacker

	tcpListener4 net.Listener
	tcpListener6 net.Listener
	mu           sync.Mutex
	running      atomic.Bool
}

type SystemStackOptions struct {
	Context    context.Context
	Tun        Tun
	Handler    StackHandler
	MTU        int
	IPv4Prefix netip.Prefix
	IPv6Prefix netip.Prefix
	UDPTimeout time.Duration

	DNSHijacker *DNSHijacker
	StrictRoute bool
}

func NewSystem(opts SystemStackOptions) (*SystemStack, error) {
	s := &SystemStack{
		ctx:         opts.Context,
		tun:         opts.Tun,
		handler:     opts.Handler,
		mtu:         opts.MTU,
		udpTimeout:  opts.UDPTimeout,
		icmpTimeout: 30 * time.Second,
		tcpNAT:      NewTCPNAT(),
		udpNAT:      NewUDPNAT(),
		dnsHijacker: opts.DNSHijacker,
		strictRoute: opts.StrictRoute,
	}

	if opts.IPv4Prefix.Addr().IsValid() {
		s.tunAddr4 = opts.IPv4Prefix.Addr()
		s.natAddr4 = s.tunAddr4.Next()
		s.dstAddr4 = s.tunAddr4
	}
	if opts.IPv6Prefix.Addr().IsValid() {
		s.tunAddr6 = opts.IPv6Prefix.Addr()
		s.natAddr6 = s.tunAddr6.Next()
		s.dstAddr6 = s.tunAddr6
	}

	return s, nil
}

func (s *SystemStack) Start() error {
	s.mu.Lock()
	if s.running.Load() {
		s.mu.Unlock()
		return nil
	}
	s.running.Store(true)
	s.mu.Unlock()

	var err error

	if s.natAddr4.IsValid() {
		lc := net.ListenConfig{}
		s.tcpListener4, err = lc.Listen(s.ctx, "tcp4", net.JoinHostPort(s.natAddr4.String(), "0"))
		if err != nil {
			s.running.Store(false)
			return err
		}
		go s.acceptTCP(s.tcpListener4, true)
	}
	if s.natAddr6.IsValid() {
		lc := net.ListenConfig{}
		s.tcpListener6, err = lc.Listen(s.ctx, "tcp6", net.JoinHostPort(s.natAddr6.String(), "0"))
		if err != nil {
			if s.tcpListener4 != nil {
				s.tcpListener4.Close()
			}
			s.running.Store(false)
			return err
		}
		go s.acceptTCP(s.tcpListener6, false)
	}

	return nil
}

// StartTunLoop begins reading from the TUN device.
// Must be called after the TUN interface is fully configured (IP addresses assigned).
func (s *SystemStack) StartTunLoop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running.Load() {
		return
	}
	go s.tunLoop()
}

func (s *SystemStack) Close() error {
	s.mu.Lock()
	s.running.Store(false)
	s.mu.Unlock()

	if s.tcpListener4 != nil {
		s.tcpListener4.Close()
	}
	if s.tcpListener6 != nil {
		s.tcpListener6.Close()
	}
	s.tun.Close()
	return nil
}

func (s *SystemStack) acceptTCP(l net.Listener, isIPv4 bool) {
	for {
		conn, err := l.Accept()
		if err != nil {
			if isTemporary(err) {
				continue
			}
			return
		}
		go s.handleAcceptedTCP(conn, isIPv4)
	}
}

func isTemporary(err error) bool {
	type temporary interface {
		Temporary() bool
	}
	t, ok := err.(temporary)
	return ok && t.Temporary()
}

func (s *SystemStack) handleAcceptedTCP(conn net.Conn, isIPv4 bool) {
	localAddr := conn.LocalAddr().(*net.TCPAddr)
	localPort := uint16(localAddr.Port)

	backSrc, backDst, ok := s.tcpNAT.LookupBack(localPort)
	if !ok {
		conn.Close()
		return
	}

	src := xnet.TCPDestination(xnet.IPAddress(backSrc.Addr().AsSlice()), xnet.Port(backSrc.Port()))
	dst := xnet.TCPDestination(xnet.IPAddress(backDst.Addr().AsSlice()), xnet.Port(backDst.Port()))

	s.handler.HandleTCP(s.ctx, conn, src, dst)
	s.tcpNAT.Delete(localPort)
}

func (s *SystemStack) tunLoop() {
	buf := make([]byte, s.mtu)
	for s.running.Load() {
		n, err := s.tun.Read(buf)
		if err != nil {
			return
		}
		if n < 20 {
			continue
		}
		s.processPacket(buf[:n])
	}
}

func (s *SystemStack) processPacket(pkt []byte) {
	version := pkt[0] >> 4
	if version == 4 {
		s.processIPv4(pkt)
	} else if version == 6 {
		s.processIPv6(pkt)
	}
}

func (s *SystemStack) processIPv4(pkt []byte) {
	if len(pkt) < 20 {
		return
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || ihl > len(pkt) {
		return
	}
	srcIP := netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]})
	dstIP := netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]})
	proto := pkt[9]

	switch proto {
	case 6:
		s.handleTCPPacket(pkt, srcIP, dstIP, ihl)
	case 17:
		s.handleUDPPacket(pkt, srcIP, dstIP, false, ihl)
	case 1:
		s.handleICMPPacket(pkt, srcIP, dstIP, false, ihl)
	}
}

func (s *SystemStack) processIPv6(pkt []byte) {
	if len(pkt) < 40 {
		return
	}
	srcIP := netip.AddrFrom16([16]byte(pkt[8:24]))
	dstIP := netip.AddrFrom16([16]byte(pkt[24:40]))
	proto := pkt[6]

	switch proto {
	case 6:
		s.handleTCPPacket(pkt, srcIP, dstIP, 40)
	case 17:
		s.handleUDPPacket(pkt, srcIP, dstIP, true, 40)
	case 58:
		s.handleICMPPacket(pkt, srcIP, dstIP, true, 40)
	}
}

func (s *SystemStack) handleTCPPacket(pkt []byte, srcIP, dstIP netip.Addr, ipHdrLen int) {
	if len(pkt) < ipHdrLen+20 {
		return
	}
	srcPort := uint16(pkt[ipHdrLen])<<8 | uint16(pkt[ipHdrLen+1])
	dstPort := uint16(pkt[ipHdrLen+2])<<8 | uint16(pkt[ipHdrLen+3])

	src := netip.AddrPortFrom(srcIP, srcPort)
	dst := netip.AddrPortFrom(dstIP, dstPort)

	_, err := s.tcpNAT.LookupOrAllocate(src, dst)
	if err != nil {
		return
	}
}

func (s *SystemStack) handleUDPPacket(pkt []byte, srcIP, dstIP netip.Addr, isIPv6 bool, ipHdrLen int) {
	if len(pkt) < ipHdrLen+8 {
		return
	}
	srcPort := uint16(pkt[ipHdrLen])<<8 | uint16(pkt[ipHdrLen+1])
	dstPort := uint16(pkt[ipHdrLen+2])<<8 | uint16(pkt[ipHdrLen+3])
	udpLen := int(uint16(pkt[ipHdrLen+4])<<8 | uint16(pkt[ipHdrLen+5]))

	if len(pkt) < ipHdrLen+udpLen {
		return
	}

	src := netip.AddrPortFrom(srcIP, srcPort)
	dst := netip.AddrPortFrom(dstIP, dstPort)
	payload := pkt[ipHdrLen+8 : ipHdrLen+udpLen]

	if s.dnsHijacker != nil {
		consumed, _ := s.dnsHijacker.Process(pkt)
		if consumed {
			return
		}
	}

	_, err := s.udpNAT.LookupOrAllocate(src, dst)
	if err != nil && s.strictRoute {
		if isIPv6 {
			icmpPkt := BuildICMPv6Unreachable(srcIP, dstIP, pkt)
			s.tun.Write(icmpPkt)
		} else {
			icmpPkt := BuildICMPv4Unreachable(srcIP, dstIP, pkt)
			s.tun.Write(icmpPkt)
		}
		return
	}

	writeBack := func(data []byte) error {
		return s.writeUDPResponse(data, dst, src, isIPv6)
	}

	s.handler.HandleUDP(s.ctx, payload,
		xnet.UDPDestination(xnet.IPAddress(srcIP.AsSlice()), xnet.Port(srcPort)),
		xnet.UDPDestination(xnet.IPAddress(dstIP.AsSlice()), xnet.Port(dstPort)),
		writeBack)
}

func (s *SystemStack) handleICMPPacket(pkt []byte, srcIP, dstIP netip.Addr, isIPv6 bool, ipHdrLen int) {
}

func (s *SystemStack) writeUDPResponse(data []byte, respSrc, respDst netip.AddrPort, isIPv6 bool) error {
	udpLen := 8 + len(data)
	var totalLen int
	var pkt []byte

	if isIPv6 {
		totalLen = 40 + udpLen
		pkt = make([]byte, totalLen)
		pkt[0] = 0x60
		binary.BigEndian.PutUint16(pkt[4:6], uint16(udpLen))
		pkt[6] = 17
		pkt[7] = 64
		rSrc16 := respSrc.Addr().As16()
		rDst16 := respDst.Addr().As16()
		copy(pkt[8:24], rSrc16[:])
		copy(pkt[24:40], rDst16[:])
	} else {
		totalLen = 20 + udpLen
		pkt = make([]byte, totalLen)
		pkt[0] = 0x45
		binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
		pkt[8] = 64
		pkt[9] = 17
		rSrc4 := respSrc.Addr().As4()
		rDst4 := respDst.Addr().As4()
		copy(pkt[12:16], rSrc4[:])
		copy(pkt[16:20], rDst4[:])
	}

	udpHdr := pkt[totalLen-udpLen:]
	binary.BigEndian.PutUint16(udpHdr[0:2], respSrc.Port())
	binary.BigEndian.PutUint16(udpHdr[2:4], respDst.Port())
	binary.BigEndian.PutUint16(udpHdr[4:6], uint16(udpLen))
	copy(udpHdr[8:], data)

	if !isIPv6 {
		binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:20]))
	}

	_, err := s.tun.Write(pkt)
	return err
}

var _ Stack = (*SystemStack)(nil)
