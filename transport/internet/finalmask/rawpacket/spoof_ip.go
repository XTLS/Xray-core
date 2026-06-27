package rawpacket

import (
	"encoding/binary"
	"net/netip"
)

func BuildIPv4Header(totalLen uint16, id uint16, ttl uint8, protocol uint8, src, dst netip.Addr) []byte {
	b := make([]byte, 20)
	b[0] = (4 << 4) | 5
	b[1] = 0
	binary.BigEndian.PutUint16(b[2:], totalLen)
	binary.BigEndian.PutUint16(b[4:], id)
	binary.BigEndian.PutUint16(b[6:], 0)
	b[8] = ttl
	b[9] = protocol
	copy(b[12:16], src.AsSlice())
	copy(b[16:20], dst.AsSlice())
	return b
}

func BuildIPv6Header(payloadLen uint16, transportProtocol uint8, hopLimit uint8, src, dst netip.Addr) []byte {
	b := make([]byte, 40)
	binary.BigEndian.PutUint32(b[0:], 6<<28)
	binary.BigEndian.PutUint16(b[4:], payloadLen)
	b[6] = transportProtocol
	b[7] = hopLimit
	copy(b[8:24], src.AsSlice())
	copy(b[24:40], dst.AsSlice())
	return b
}

func IPv4PseudoHeaderChecksum(src, dst netip.Addr, protocol uint8, tcpLen uint16) uint16 {
	var csum uint32
	srcB := src.As4()
	dstB := dst.As4()
	for i := 0; i < 4; i += 2 {
		csum += uint32(binary.BigEndian.Uint16(srcB[i:]))
	}
	for i := 0; i < 4; i += 2 {
		csum += uint32(binary.BigEndian.Uint16(dstB[i:]))
	}
	csum += uint32(protocol)
	csum += uint32(tcpLen)
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return uint16(csum)
}

func IPv6PseudoHeaderChecksum(src, dst netip.Addr, protocol uint8, totalLen uint32) uint16 {
	var csum uint32
	srcB := src.As16()
	dstB := dst.As16()
	for i := 0; i < 16; i += 2 {
		csum += uint32(binary.BigEndian.Uint16(srcB[i:]))
	}
	for i := 0; i < 16; i += 2 {
		csum += uint32(binary.BigEndian.Uint16(dstB[i:]))
	}
	csum += uint32(protocol)
	csum += totalLen
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return uint16(csum)
}


