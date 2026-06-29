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
	tcpNAT      *TCPNAT
	udpNAT      *UDPNAT
	udpTimeout  time.Duration
	icmpTimeout time.Duration

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
	}

	if opts.IPv4Prefix.Addr().IsValid() {
		s.tunAddr4 = opts.IPv4Prefix.Addr()
		s.natAddr4 = s.tunAddr4.Next()
	}
	if opts.IPv6Prefix.Addr().IsValid() {
		s.tunAddr6 = opts.IPv6Prefix.Addr()
		s.natAddr6 = s.tunAddr6.Next()
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

	go s.tunLoop()
	return nil
}

func (s *SystemStack) Close() error {
	s.running.Store(false)

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
			return
		}
		go s.handleAcceptedTCP(conn, isIPv4)
	}
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

	_ = s.handler.HandleTCP(s.ctx, conn, src, dst)
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
	srcIP := netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]})
	dstIP := netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]})
	proto := pkt[9]

	switch proto {
	case 6:
		s.handleTCPPacket(pkt, srcIP, dstIP)
	case 17:
		s.handleUDPPacket(pkt, srcIP, dstIP, false)
	case 1:
		s.handleICMPPacket(pkt, srcIP, dstIP, false)
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
		s.handleTCPPacket(pkt, srcIP, dstIP)
	case 17:
		s.handleUDPPacket(pkt, srcIP, dstIP, true)
	case 58:
		s.handleICMPPacket(pkt, srcIP, dstIP, true)
	}
}

func (s *SystemStack) handleTCPPacket(pkt []byte, srcIP, dstIP netip.Addr) {
	if len(pkt) < 40 {
		return
	}
	srcPort := uint16(pkt[20])<<8 | uint16(pkt[21])
	dstPort := uint16(pkt[22])<<8 | uint16(pkt[23])

	src := netip.AddrPortFrom(srcIP, srcPort)
	dst := netip.AddrPortFrom(dstIP, dstPort)

	_, err := s.tcpNAT.LookupOrAllocate(src, dst)
	if err != nil {
		return
	}
}

func (s *SystemStack) handleUDPPacket(pkt []byte, srcIP, dstIP netip.Addr, isIPv6 bool) {
	if len(pkt) < 28 {
		return
	}
	srcPort := uint16(pkt[20])<<8 | uint16(pkt[21])
	dstPort := uint16(pkt[22])<<8 | uint16(pkt[23])
	udpLen := int(uint16(pkt[24])<<8 | uint16(pkt[25]))

	if len(pkt) < 20+udpLen {
		return
	}

	src := netip.AddrPortFrom(srcIP, srcPort)
	dst := netip.AddrPortFrom(dstIP, dstPort)
	payload := pkt[28 : 20+udpLen]

	writeBack := func(data []byte) error {
		return s.writeUDPResponse(data, dst, src, isIPv6)
	}

	_ = s.handler.HandleUDP(s.ctx, payload,
		xnet.UDPDestination(xnet.IPAddress(srcIP.AsSlice()), xnet.Port(srcPort)),
		xnet.UDPDestination(xnet.IPAddress(dstIP.AsSlice()), xnet.Port(dstPort)),
		writeBack)
}

func (s *SystemStack) handleICMPPacket(pkt []byte, srcIP, dstIP netip.Addr, isIPv6 bool) {
}

func (s *SystemStack) writeUDPResponse(data []byte, src, dst netip.AddrPort, isIPv6 bool) error {
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
		src16 := src.Addr().As16()
		dst16 := dst.Addr().As16()
		copy(pkt[8:24], src16[:])
		copy(pkt[24:40], dst16[:])
	} else {
		totalLen = 20 + udpLen
		pkt = make([]byte, totalLen)
		pkt[0] = 0x45
		binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
		pkt[8] = 64
		pkt[9] = 17
		src4 := src.Addr().As4()
		dst4 := dst.Addr().As4()
		copy(pkt[12:16], src4[:])
		copy(pkt[16:20], dst4[:])
	}

	udpHdr := pkt[totalLen-udpLen:]
	binary.BigEndian.PutUint16(udpHdr[0:2], src.Port())
	binary.BigEndian.PutUint16(udpHdr[2:4], dst.Port())
	binary.BigEndian.PutUint16(udpHdr[4:6], uint16(udpLen))
	copy(udpHdr[8:], data)

	if !isIPv6 {
		binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:20]))
	}

	_, err := s.tun.Write(pkt)
	return err
}

var _ Stack = (*SystemStack)(nil)
