package icmp

import (
	"encoding/binary"
	stdnet "net"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
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

func Payload(message []byte) []byte {
	if len(message) < header.ICMPv4PayloadOffset {
		return nil
	}
	return append([]byte(nil), message[header.ICMPv4PayloadOffset:]...)
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

func MatchEchoReply(netProto tcpip.NetworkProtocolNumber, message []byte, ident, sequence, altIdent uint16, hasAltIdent bool) (uint16, bool) {
	if isMatchingEchoReply(netProto, message, ident, sequence) {
		return ident, true
	}
	if hasAltIdent && altIdent != ident && isMatchingEchoReply(netProto, message, altIdent, sequence) {
		return altIdent, true
	}
	return 0, false
}

func isMatchingEchoReply(netProto tcpip.NetworkProtocolNumber, message []byte, ident, sequence uint16) bool {
	switch netProto {
	case header.IPv4ProtocolNumber:
		if len(message) < header.ICMPv4MinimumSize {
			return false
		}
		icmpHdr := header.ICMPv4(message)
		return icmpHdr.Type() == header.ICMPv4EchoReply &&
			icmpHdr.Code() == header.ICMPv4UnusedCode &&
			icmpHdr.Ident() == ident &&
			icmpHdr.Sequence() == sequence
	case header.IPv6ProtocolNumber:
		if len(message) < header.ICMPv6MinimumSize {
			return false
		}
		icmpHdr := header.ICMPv6(message)
		return icmpHdr.Type() == header.ICMPv6EchoReply &&
			icmpHdr.Code() == header.ICMPv6UnusedCode &&
			icmpHdr.Ident() == ident &&
			icmpHdr.Sequence() == sequence
	default:
		return false
	}
}

func NormalizeEchoReply(netProto tcpip.NetworkProtocolNumber, message []byte) ([]byte, error) {
	switch netProto {
	case header.IPv4ProtocolNumber:
		if len(message) >= header.IPv4MinimumSize && message[0]>>4 == 4 {
			headerLen := int(message[0]&0x0f) * 4
			if headerLen < header.IPv4MinimumSize || headerLen > len(message) {
				return nil, errors.New("invalid ipv4 header in icmp reply")
			}
			return message[headerLen:], nil
		}
	case header.IPv6ProtocolNumber:
		if len(message) >= header.IPv6MinimumSize && message[0]>>4 == 6 {
			if len(message) < header.IPv6MinimumSize {
				return nil, errors.New("invalid ipv6 header in icmp reply")
			}
			return message[header.IPv6MinimumSize:], nil
		}
	}
	return message, nil
}

func MarshalEchoMessage(netProto tcpip.NetworkProtocolNumber, request bool, ident, sequence uint16, payload []byte) ([]byte, error) {
	msg := icmp.Message{
		Code: 0,
		Body: &icmp.Echo{
			ID:   int(ident),
			Seq:  int(sequence),
			Data: payload,
		},
	}

	switch netProto {
	case header.IPv4ProtocolNumber:
		if request {
			msg.Type = ipv4.ICMPTypeEcho
		} else {
			msg.Type = ipv4.ICMPTypeEchoReply
		}
	case header.IPv6ProtocolNumber:
		if request {
			msg.Type = ipv6.ICMPTypeEchoRequest
		} else {
			msg.Type = ipv6.ICMPTypeEchoReply
		}
	default:
		return nil, errors.New("unsupported icmp network protocol")
	}

	return msg.Marshal(nil)
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

func RewriteEchoIdentifier(netProto tcpip.NetworkProtocolNumber, message []byte, ident uint16) error {
	switch netProto {
	case header.IPv4ProtocolNumber:
		if len(message) < header.ICMPv4MinimumSize {
			return errors.New("invalid icmpv4 echo packet")
		}
	case header.IPv6ProtocolNumber:
		if len(message) < header.ICMPv6MinimumSize {
			return errors.New("invalid icmpv6 echo packet")
		}
	default:
		return errors.New("unsupported icmp network protocol")
	}

	binary.BigEndian.PutUint16(message[4:6], ident)
	return nil
}

func IsDatagramNetwork(network string) bool {
	return network == "udp4" || network == "udp6"
}

func DatagramEchoIdentifier(addr stdnet.Addr) (uint16, bool) {
	udpAddr, ok := addr.(*stdnet.UDPAddr)
	if !ok || udpAddr.Port < 0 || udpAddr.Port > 0xffff {
		return 0, false
	}
	return uint16(udpAddr.Port), true
}

func ReplyAddrMatches(addr, expected stdnet.Addr) bool {
	addrIPValue := addrIP(addr)
	expectedIPValue := addrIP(expected)
	return addrIPValue != nil && expectedIPValue != nil && addrIPValue.Equal(expectedIPValue)
}

func addrIP(addr stdnet.Addr) stdnet.IP {
	switch addr := addr.(type) {
	case *stdnet.IPAddr:
		return addr.IP
	case *stdnet.UDPAddr:
		return addr.IP
	default:
		return nil
	}
}
