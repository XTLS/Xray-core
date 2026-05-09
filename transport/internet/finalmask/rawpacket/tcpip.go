package rawpacket

import (
	"encoding/binary"
	"net/netip"
)

const (
	IPv4MinimumSize   = 20
	IPv6MinimumSize   = 40
	TCPMinimumSize    = 20
	TCPProtocolNumber = 6

	TCPOptionEOL = 0
	TCPOptionNOP = 1
	TCPOptionTS  = 8
	TCPOptionTSLength = 10
	
	TCPFlagFin = 0x01
	TCPFlagSyn = 0x02
	TCPFlagRst = 0x04
	TCPFlagPsh = 0x08
	TCPFlagAck = 0x10
)

func Checksum(data []byte, initial uint16) uint16 {
	var csum uint32 = uint32(initial)
	for i := 0; i < len(data)-1; i += 2 {
		csum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		csum += uint32(data[len(data)-1]) << 8
	}
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return uint16(csum)
}

func PseudoHeaderChecksum(protocol uint8, srcAddr, dstAddr []byte, totalLen uint16) uint16 {
	var csum uint32
	for i := 0; i < len(srcAddr); i += 2 {
		csum += uint32(binary.BigEndian.Uint16(srcAddr[i:]))
	}
	for i := 0; i < len(dstAddr); i += 2 {
		csum += uint32(binary.BigEndian.Uint16(dstAddr[i:]))
	}
	csum += uint32(protocol)
	csum += uint32(totalLen)
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return uint16(csum)
}

func CombineChecksum(c1, c2 uint16) uint16 {
	csum := uint32(c1) + uint32(c2)
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return uint16(csum)
}

func EncodeTSOption(val uint32, ecr uint32, b []byte) {
	b[0] = TCPOptionTS
	b[1] = TCPOptionTSLength
	binary.BigEndian.PutUint32(b[2:], val)
	binary.BigEndian.PutUint32(b[6:], ecr)
}

func ParseTCPOptions(b []byte) (tsVal uint32, hasTS bool) {
	for i := 0; i < len(b); {
		if b[i] == TCPOptionEOL {
			break
		}
		if b[i] == TCPOptionNOP {
			i++
			continue
		}
		if i+1 >= len(b) {
			break
		}
		optLen := int(b[i+1])
		if optLen < 2 || i+optLen > len(b) {
			break
		}
		if b[i] == TCPOptionTS && optLen == TCPOptionTSLength {
			return binary.BigEndian.Uint32(b[i+2:]), true
		}
		i += optLen
	}
	return 0, false
}

// IPv4 header representation
type IPv4 []byte

func (b IPv4) TotalLength() uint16 { return binary.BigEndian.Uint16(b[2:]) }
func (b IPv4) Flags() uint8 { return uint8(binary.BigEndian.Uint16(b[6:]) >> 13) }
func (b IPv4) FragmentOffset() uint16 { return binary.BigEndian.Uint16(b[6:]) & 0x1fff }
func (b IPv4) Protocol() uint8 { return b[9] }
func (b IPv4) HeaderLength() uint8 { return (b[0] & 0x0f) * 4 }

func (b IPv4) Encode(totalLength uint16, id uint16, ttl uint8, protocol uint8, src, dst netip.Addr) {
	b[0] = (4 << 4) | 5 // IPv4, Header Length = 20
	b[1] = 0 // TOS
	binary.BigEndian.PutUint16(b[2:], totalLength)
	binary.BigEndian.PutUint16(b[4:], id)
	binary.BigEndian.PutUint16(b[6:], 0) // Flags and Fragment Offset
	b[8] = ttl
	b[9] = protocol
	b[10] = 0 // Checksum (0 for calculation)
	copy(b[12:16], src.AsSlice())
	copy(b[16:20], dst.AsSlice())
	csum := Checksum(b[:20], 0)
	binary.BigEndian.PutUint16(b[10:], ^csum)
}

type IPv6 []byte

func (b IPv6) PayloadLength() uint16 { return binary.BigEndian.Uint16(b[4:]) }
func (b IPv6) TransportProtocol() uint8 { return b[6] }

func (b IPv6) Encode(payloadLength uint16, transportProtocol uint8, hopLimit uint8, src, dst netip.Addr) {
	binary.BigEndian.PutUint32(b[0:], 6<<28) // Version 6, Traffic Class 0, Flow Label 0
	binary.BigEndian.PutUint16(b[4:], payloadLength)
	b[6] = transportProtocol
	b[7] = hopLimit
	copy(b[8:24], src.AsSlice())
	copy(b[24:40], dst.AsSlice())
}

type TCP []byte

func (b TCP) DataOffset() uint8 { return (b[12] >> 4) * 4 }
func (b TCP) SequenceNumber() uint32 { return binary.BigEndian.Uint32(b[4:]) }
func (b TCP) AckNumber() uint32 { return binary.BigEndian.Uint32(b[8:]) }
func (b TCP) Options() []byte { return b[TCPMinimumSize:b.DataOffset()] }
func (b TCP) SetChecksum(csum uint16) { binary.BigEndian.PutUint16(b[16:], csum) }

func (b TCP) Encode(srcPort, dstPort uint16, seqNum, ackNum uint32, dataOffset uint8, flags uint8, windowSize uint16) {
	binary.BigEndian.PutUint16(b[0:], srcPort)
	binary.BigEndian.PutUint16(b[2:], dstPort)
	binary.BigEndian.PutUint32(b[4:], seqNum)
	binary.BigEndian.PutUint32(b[8:], ackNum)
	b[12] = (dataOffset / 4) << 4
	b[13] = flags
	binary.BigEndian.PutUint16(b[14:], windowSize)
	b[16] = 0 // Checksum
	binary.BigEndian.PutUint16(b[18:], 0) // Urgent pointer
}

func (b TCP) CalculateChecksum(initial uint16) uint16 {
	return Checksum(b, initial)
}
