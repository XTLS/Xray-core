package rawpacket

import "net/netip"

type SpoofSender interface {
	Send(payload []byte, dstIP netip.Addr, dstPort uint16, tcp *TCPSimState) error
	Close() error
}

// TCPMeta carries the header fields of a received raw packet so the
// caller can keep the fake conversation's sequence/ack state plausible,
// and the relay can masquerade replies from the address the probe dialed.
// DstIP/DstPort are always set; Seq/Flags are non-zero only for TCP.
// nil for transports the receiver does not describe (ICMP).
type TCPMeta struct {
	Seq     uint32
	Flags   uint8
	DstIP   netip.Addr
	DstPort uint16
}

type SpoofReceiver interface {
	Receive() (payload []byte, srcIP netip.Addr, srcPort uint16, tcp *TCPMeta, err error)
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
	// Server marks a relay-side sender: outbound TCP segments take the
	// passive-opener role (SYN|ACK then ACK).
	Server bool
}

type SpoofReceiverConfig struct {
	ListenPort  uint16
	PeerSpoofIP netip.Addr
	BufferSize  int
}
