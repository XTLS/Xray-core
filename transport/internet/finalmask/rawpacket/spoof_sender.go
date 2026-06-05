package rawpacket

import (
	"math/rand"
	"net/netip"
	"sync"
)

type tcpSender struct {
	srcIPs  []netip.Addr
	rotator *SourceIPRotator
	srcPort uint16
	ttl     uint8
	seqNum  uint32
	seqMu   sync.Mutex
	fd      *rawSendFD
}

func newTCPSender(cfg *SpoofSenderConfig) (*tcpSender, error) {
	ips := cfg.SourceIPs
	if len(ips) == 0 {
		ips = []netip.Addr{cfg.SourceIP}
	}
	fd, err := openRawSender(ips[0])
	if err != nil {
		return nil, err
	}
	return &tcpSender{
		srcIPs:  ips,
		rotator: NewSourceIPRotator(ips),
		srcPort: cfg.SourcePort,
		ttl:     cfg.TTL,
		seqNum:  uint32(rand.Int63n(1 << 31)),
		fd:      fd,
	}, nil
}

func (s *tcpSender) Send(payload []byte, dstIP netip.Addr, dstPort uint16) error {
	s.seqMu.Lock()
	seq := s.seqNum
	s.seqNum += uint32(len(payload))
	s.seqMu.Unlock()

	spoofIP := s.rotator.Next()
	pkt := BuildTCPSYN(spoofIP, dstIP, s.srcPort, dstPort, seq, payload, s.ttl)
	return s.fd.send(pkt)
}

func (s *tcpSender) Close() error {
	if s.fd != nil {
		s.fd.close()
	}
	return nil
}

type udpSender struct {
	srcIPs  []netip.Addr
	rotator *SourceIPRotator
	srcPort uint16
	ttl     uint8
	fd      *rawSendFD
}

func newUDPSender(cfg *SpoofSenderConfig) (*udpSender, error) {
	ips := cfg.SourceIPs
	if len(ips) == 0 {
		ips = []netip.Addr{cfg.SourceIP}
	}
	fd, err := openRawSender(ips[0])
	if err != nil {
		return nil, err
	}
	return &udpSender{
		srcIPs:  ips,
		rotator: NewSourceIPRotator(ips),
		srcPort: cfg.SourcePort,
		ttl:     cfg.TTL,
		fd:      fd,
	}, nil
}

func (s *udpSender) Send(payload []byte, dstIP netip.Addr, dstPort uint16) error {
	spoofIP := s.rotator.Next()
	pkt := BuildRawUDP(spoofIP, dstIP, s.srcPort, dstPort, payload, s.ttl)
	return s.fd.send(pkt)
}

func (s *udpSender) Close() error {
	if s.fd != nil {
		s.fd.close()
	}
	return nil
}

type icmpSender struct {
	srcIPs  []netip.Addr
	rotator *SourceIPRotator
	id      uint16
	seq     uint16
	ttl     uint8
	seqMu   sync.Mutex
	fd      *rawSendFD
}

func newICMPSender(cfg *SpoofSenderConfig) (*icmpSender, error) {
	ips := cfg.SourceIPs
	if len(ips) == 0 {
		ips = []netip.Addr{cfg.SourceIP}
	}
	fd, err := openRawSender(ips[0])
	if err != nil {
		return nil, err
	}
	return &icmpSender{
		srcIPs:  ips,
		rotator: NewSourceIPRotator(ips),
		id:      cfg.SourcePort,
		seq:     1,
		ttl:     cfg.TTL,
		fd:      fd,
	}, nil
}

func (s *icmpSender) Send(payload []byte, dstIP netip.Addr, dstPort uint16) error {
	s.seqMu.Lock()
	seq := s.seq
	s.seq++
	s.seqMu.Unlock()

	spoofIP := s.rotator.Next()
	pkt := BuildICMPv4Echo(spoofIP, dstIP, s.id, seq, payload, s.ttl)
	return s.fd.send(pkt)
}

func (s *icmpSender) Close() error {
	if s.fd != nil {
		s.fd.close()
	}
	return nil
}

type icmpv6Sender struct {
	srcIPs  []netip.Addr
	rotator *SourceIPRotator
	id      uint16
	seq     uint16
	ttl     uint8
	seqMu   sync.Mutex
	fd      *rawSendFD
}

func newICMPv6Sender(cfg *SpoofSenderConfig) (*icmpv6Sender, error) {
	ips := cfg.SourceIPs
	if len(ips) == 0 {
		ips = []netip.Addr{cfg.SourceIP}
	}
	fd, err := openRawSender(ips[0])
	if err != nil {
		return nil, err
	}
	return &icmpv6Sender{
		srcIPs:  ips,
		rotator: NewSourceIPRotator(ips),
		id:      cfg.SourcePort,
		seq:     1,
		ttl:     cfg.TTL,
		fd:      fd,
	}, nil
}

func (s *icmpv6Sender) Send(payload []byte, dstIP netip.Addr, dstPort uint16) error {
	s.seqMu.Lock()
	seq := s.seq
	s.seq++
	s.seqMu.Unlock()

	spoofIP := s.rotator.Next()
	pkt := BuildICMPv6Echo(spoofIP, dstIP, s.id, seq, payload, s.ttl)
	return s.fd.send(pkt)
}

func (s *icmpv6Sender) Close() error {
	if s.fd != nil {
		s.fd.close()
	}
	return nil
}
