package tun

import (
	"encoding/binary"
	"net/netip"
)

const (
	icmpv4TypeUnreachable      = 3
	icmpv4CodePortUnreachable   = 3
	icmpv6TypeUnreachable      = 1
	icmpv6CodePortUnreachable   = 4
)

func BuildICMPv4Unreachable(origSrc, origDst netip.Addr, origPayload []byte) []byte {
	ipHeaderLen := 20
	icmpHeaderLen := 8
	origHeaderLen := 28

	payloadLen := icmpHeaderLen + origHeaderLen
	totalLen := ipHeaderLen + payloadLen

	pkt := make([]byte, totalLen)

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = 1

	src4 := origDst.As4()
	dst4 := origSrc.As4()
	copy(pkt[12:16], src4[:])
	copy(pkt[16:20], dst4[:])

	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:20]))

	pkt[20] = icmpv4TypeUnreachable
	pkt[21] = icmpv4CodePortUnreachable

	n := origHeaderLen
	if len(origPayload) < n {
		n = len(origPayload)
	}
	copy(pkt[28:28+n], origPayload[:n])

	binary.BigEndian.PutUint16(pkt[22:24], ipChecksum(pkt[20:28+n]))

	return pkt
}

func BuildICMPv6Unreachable(origSrc, origDst netip.Addr, origPayload []byte) []byte {
	ipv6HeaderLen := 40
	icmpHeaderLen := 8
	origHeaderLen := 48

	payloadLen := icmpHeaderLen + origHeaderLen
	totalLen := ipv6HeaderLen + payloadLen

	pkt := make([]byte, totalLen)

	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(payloadLen))
	pkt[6] = 58
	pkt[7] = 64

	src16 := origDst.As16()
	dst16 := origSrc.As16()
	copy(pkt[8:24], src16[:])
	copy(pkt[24:40], dst16[:])

	pkt[40] = icmpv6TypeUnreachable
	pkt[41] = icmpv6CodePortUnreachable

	n := origHeaderLen
	if len(origPayload) < n {
		n = len(origPayload)
	}
	copy(pkt[48:48+n], origPayload[:n])

	binary.BigEndian.PutUint16(pkt[42:44], icmpv6Checksum(pkt[40:48+n], origDst, origSrc))

	return pkt
}

func ipChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		if i+1 < len(data) {
			sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
		} else {
			sum += uint32(data[i]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func icmpv6Checksum(icmpPacket []byte, src, dst netip.Addr) uint16 {
	sum := uint32(0)

	src16 := src.As16()
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(src16[i : i+2]))
	}

	dst16 := dst.As16()
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(dst16[i : i+2]))
	}

	sum += uint32(len(icmpPacket))
	sum += 58

	for i := 0; i < len(icmpPacket); i += 2 {
		if i+1 < len(icmpPacket) {
			sum += uint32(binary.BigEndian.Uint16(icmpPacket[i : i+2]))
		} else {
			sum += uint32(icmpPacket[i]) << 8
		}
	}

	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
