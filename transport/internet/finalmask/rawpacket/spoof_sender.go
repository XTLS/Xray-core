package rawpacket

import (
	"math/rand"
	"net/netip"
	"sync"
)

type tcpSender struct {
	srcIP   netip.Addr
	srcPort uint16
	ttl     uint8
	ipID    uint16
	server  bool
	fd      *rawSendFD
	mu      sync.Mutex
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
		srcIP:   ips[0],
		srcPort: cfg.SourcePort,
		ttl:     cfg.TTL,
		ipID:    uint16(rand.Intn(65535)),
		server:  cfg.Server,
		fd:      fd,
	}, nil
}

func (s *tcpSender) nextIPID() uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ipID++
	return s.ipID
}

func (s *tcpSender) Send(payload []byte, dstIP netip.Addr, dstPort uint16, tcp *TCPSimState) error {
	if tcp == nil {
		return nil
	}
	seq := tcp.nextSeq(len(payload))
	var flags uint8
	if s.server {
		flags = tcp.serverFlags()
	} else {
		flags = tcp.clientFlags()
	}
	pkt := BuildTCPPacket(s.srcIP, dstIP, s.srcPort, dstPort, seq, tcp.ack(), flags, payload, s.ttl, s.nextIPID(), flags&TCPFlagSyn != 0)
	return s.fd.send(pkt)
}

func (s *tcpSender) Close() error {
	if s.fd != nil {
		s.fd.close()
	}
	return nil
}

type udpSender struct {
	srcIP   netip.Addr
	srcPort uint16
	ttl     uint8
	ipID    uint16
	fd      *rawSendFD
	mu      sync.Mutex
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
		srcIP:   ips[0],
		srcPort: cfg.SourcePort,
		ttl:     cfg.TTL,
		ipID:    uint16(rand.Intn(65535)),
		fd:      fd,
	}, nil
}

func (s *udpSender) nextIPID() uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ipID++
	return s.ipID
}

func (s *udpSender) Send(payload []byte, dstIP netip.Addr, dstPort uint16, tcp *TCPSimState) error {
	pkt := BuildRawUDP(s.srcIP, dstIP, s.srcPort, dstPort, payload, s.ttl, s.nextIPID())
	return s.fd.send(pkt)
}

func (s *udpSender) Close() error {
	if s.fd != nil {
		s.fd.close()
	}
	return nil
}

type icmpSender struct {
	srcIP netip.Addr
	id    uint16
	seq   uint16
	ttl   uint8
	ipID  uint16
	seqMu sync.Mutex
	fd    *rawSendFD
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
		srcIP: ips[0],
		id:    cfg.SourcePort,
		seq:   1,
		ttl:   cfg.TTL,
		ipID:  uint16(rand.Intn(65535)),
		fd:    fd,
	}, nil
}

func (s *icmpSender) nextIPID() uint16 {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	s.ipID++
	return s.ipID
}

func (s *icmpSender) Send(payload []byte, dstIP netip.Addr, dstPort uint16, tcp *TCPSimState) error {
	s.seqMu.Lock()
	seq := s.seq
	s.seq++
	s.seqMu.Unlock()

	pkt := BuildICMPv4Echo(s.srcIP, dstIP, s.id, seq, payload, s.ttl, s.nextIPID())
	return s.fd.send(pkt)
}

func (s *icmpSender) Close() error {
	if s.fd != nil {
		s.fd.close()
	}
	return nil
}

type icmpv6Sender struct {
	srcIP netip.Addr
	id    uint16
	seq   uint16
	ttl   uint8
	ipID  uint16
	seqMu sync.Mutex
	fd    *rawSendFD
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
		srcIP: ips[0],
		id:    cfg.SourcePort,
		seq:   1,
		ttl:   cfg.TTL,
		ipID:  uint16(rand.Intn(65535)),
		fd:    fd,
	}, nil
}

func (s *icmpv6Sender) nextIPID() uint16 {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	s.ipID++
	return s.ipID
}

func (s *icmpv6Sender) Send(payload []byte, dstIP netip.Addr, dstPort uint16, tcp *TCPSimState) error {
	s.seqMu.Lock()
	seq := s.seq
	s.seq++
	s.seqMu.Unlock()

	pkt := BuildICMPv6Echo(s.srcIP, dstIP, s.id, seq, payload, s.ttl, s.nextIPID())
	return s.fd.send(pkt)
}

func (s *icmpv6Sender) Close() error {
	if s.fd != nil {
		s.fd.close()
	}
	return nil
}
