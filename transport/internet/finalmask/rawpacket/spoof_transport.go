package rawpacket

import "net/netip"

type SpoofSender interface {
	Send(payload []byte, dstIP netip.Addr, dstPort uint16) error
	Close() error
}

type SpoofReceiver interface {
	Receive() (payload []byte, srcIP netip.Addr, srcPort uint16, err error)
	Close() error
}

func NewSender(transport string, cfg *SpoofSenderConfig) (SpoofSender, error) {
	switch transport {
	case "tcp", "":
		return newTCPSender(cfg)
	case "udp":
		return newUDPSender(cfg)
	case "icmp":
		return newICMPSender(cfg)
	case "icmpv6":
		return newICMPv6Sender(cfg)
	}
	return nil, nil
}

func NewReceiver(transport string, cfg *SpoofReceiverConfig) (SpoofReceiver, error) {
	switch transport {
	case "tcp", "":
		return newTCPReceiver(cfg)
	case "udp":
		return newUDPReceiver(cfg)
	case "icmp":
		return newICMPReceiver(cfg)
	case "icmpv6":
		return newICMPv6Receiver(cfg)
	}
	return nil, nil
}

type SpoofSenderConfig struct {
	SourceIP   netip.Addr
	SourceIPs  []netip.Addr
	SourcePort uint16
	TTL        uint8
}

type SpoofReceiverConfig struct {
	ListenPort  uint16
	PeerSpoofIP netip.Addr
	BufferSize  int
}
