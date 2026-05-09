package icmp

import (
	"github.com/xtls/xray-core/common/errors"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func ProtocolLabel(netProto tcpip.NetworkProtocolNumber) string {
	switch netProto {
	case header.IPv4ProtocolNumber:
		return "ipv4"
	case header.IPv6ProtocolNumber:
		return "ipv6"
	default:
		return "unknown"
	}
}

func ParseEchoRequest(netProto tcpip.NetworkProtocolNumber, message []byte) (uint16, uint16, bool) {
	switch netProto {
	case header.IPv4ProtocolNumber:
		if len(message) < header.ICMPv4MinimumSize {
			return 0, 0, false
		}
		icmpHdr := header.ICMPv4(message)
		if icmpHdr.Type() != header.ICMPv4Echo || icmpHdr.Code() != header.ICMPv4UnusedCode {
			return 0, 0, false
		}
		return icmpHdr.Ident(), icmpHdr.Sequence(), true
	case header.IPv6ProtocolNumber:
		if len(message) < header.ICMPv6MinimumSize {
			return 0, 0, false
		}
		icmpHdr := header.ICMPv6(message)
		if icmpHdr.Type() != header.ICMPv6EchoRequest || icmpHdr.Code() != header.ICMPv6UnusedCode {
			return 0, 0, false
		}
		return icmpHdr.Ident(), icmpHdr.Sequence(), true
	default:
		return 0, 0, false
	}
}

func RewriteChecksum(netProto tcpip.NetworkProtocolNumber, message []byte, srcIP, dstIP tcpip.Address) error {
	switch netProto {
	case header.IPv4ProtocolNumber:
		if len(message) < header.ICMPv4MinimumSize {
			return errors.New("invalid icmpv4 packet")
		}
		icmpHdr := header.ICMPv4(message)
		icmpHdr.SetChecksum(0)
		icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr[:header.ICMPv4MinimumSize], checksum.Checksum(icmpHdr.Payload(), 0)))
		return nil
	case header.IPv6ProtocolNumber:
		if len(message) < header.ICMPv6MinimumSize {
			return errors.New("invalid icmpv6 packet")
		}
		icmpHdr := header.ICMPv6(message)
		icmpHdr.SetChecksum(0)
		icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header:      icmpHdr[:header.ICMPv6MinimumSize],
			Src:         srcIP,
			Dst:         dstIP,
			PayloadCsum: checksum.Checksum(icmpHdr.Payload(), 0),
			PayloadLen:  len(icmpHdr.Payload()),
		}))
		return nil
	default:
		return errors.New("unsupported icmp network protocol")
	}
}

func BuildLocalEchoReply(netProto tcpip.NetworkProtocolNumber, request []byte, srcIP, dstIP tcpip.Address) ([]byte, error) {
	reply := append([]byte(nil), request...)

	switch netProto {
	case header.IPv4ProtocolNumber:
		if len(reply) < header.ICMPv4MinimumSize {
			return nil, errors.New("invalid icmpv4 echo packet")
		}
		icmpHdr := header.ICMPv4(reply)
		if icmpHdr.Type() != header.ICMPv4Echo || icmpHdr.Code() != header.ICMPv4UnusedCode {
			return nil, errors.New("not an icmpv4 echo request")
		}
		reply[0] = byte(header.ICMPv4EchoReply)
	case header.IPv6ProtocolNumber:
		if len(reply) < header.ICMPv6MinimumSize {
			return nil, errors.New("invalid icmpv6 echo packet")
		}
		icmpHdr := header.ICMPv6(reply)
		if icmpHdr.Type() != header.ICMPv6EchoRequest || icmpHdr.Code() != header.ICMPv6UnusedCode {
			return nil, errors.New("not an icmpv6 echo request")
		}
		reply[0] = byte(header.ICMPv6EchoReply)
	default:
		return nil, errors.New("unsupported icmp network protocol")
	}

	if err := RewriteChecksum(netProto, reply, srcIP, dstIP); err != nil {
		return nil, err
	}

	return reply, nil
}
