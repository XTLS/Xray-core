package rawpacket

import (
	"fmt"
	"net/netip"
	"strings"
)

const (
	ProtocolTCP    uint8 = 6
	ProtocolICMP   uint8 = 1
	ProtocolICMPv6 uint8 = 58
	ProtocolUDP    uint8 = 17
)

func ParseProtocol(s string) (uint8, error) {
	switch strings.ToLower(s) {
	case "tcp":
		return ProtocolTCP, nil
	case "icmp":
		return ProtocolICMP, nil
	case "icmpv6":
		return ProtocolICMPv6, nil
	case "udp":
		return ProtocolUDP, nil
	default:
		return 0, fmt.Errorf("rawpacket: unknown protocol: %s", s)
	}
}

func ParseIPs(ss []string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, s := range ss {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("rawpacket: invalid spoof IP %q: %w", s, err)
		}
		out = append(out, ip.Unmap())
	}
	return out, nil
}

type RelayConfig struct {
	ListenPort      uint16
	ForwardAddr     string
	ForwardTransport string // "tcp" (Xray) or "udp" (reference, default)
	ClientIP        netip.Addr
	ClientPort      uint16
	SpoofIP         netip.Addr // single fallback
	SpoofIPs        []string
	SpoofPort       uint16
	PeerSpoofIP     netip.Addr
	SendTransport   string
	RecvTransport   string
	icmpSuppressed  bool
}
