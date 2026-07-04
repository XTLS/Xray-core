package rawpacket

import (
	"encoding/binary"
	"math/rand"
	"net/netip"
)

func BuildTCPSYN(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, seqNum uint32, payload []byte, ttl uint8) []byte {
	ipHdrLen := 20
	tcpHdrLen := 20
	totalLen := ipHdrLen + tcpHdrLen + len(payload)

	frame := make([]byte, totalLen)
	ip := BuildIPv4Header(uint16(totalLen), uint16(rand.Intn(65535)), ttl, 6, srcIP, dstIP)
	copy(frame, ip)

	tcp := frame[ipHdrLen:]
	binary.BigEndian.PutUint16(tcp[0:], srcPort)
	binary.BigEndian.PutUint16(tcp[2:], dstPort)
	binary.BigEndian.PutUint32(tcp[4:], seqNum)
	binary.BigEndian.PutUint32(tcp[8:], 0)
	tcp[12] = byte((tcpHdrLen / 4) << 4)
	tcp[13] = TCPFlagSyn
	binary.BigEndian.PutUint16(tcp[14:], 65535)

	if len(payload) > 0 {
		copy(frame[ipHdrLen+tcpHdrLen:], payload)
	}

	pseudo := IPv4PseudoHeaderChecksum(srcIP, dstIP, 6, uint16(tcpHdrLen+len(payload)))
	csum := Checksum(tcp[:tcpHdrLen+len(payload)], pseudo)
	binary.BigEndian.PutUint16(tcp[16:], ^csum)

	return frame
}

func BuildICMPv4Echo(srcIP, dstIP netip.Addr, id, seq uint16, payload []byte, ttl uint8) []byte {
	totalLen := 20 + 8 + len(payload)
	frame := make([]byte, totalLen)
	ip := BuildIPv4Header(uint16(totalLen), uint16(rand.Intn(65535)), ttl, 1, srcIP, dstIP)
	copy(frame, ip)

	icmp := frame[20:]
	icmp[0] = 8  // Echo Request
	icmp[1] = 0
	binary.BigEndian.PutUint16(icmp[4:], id)
	binary.BigEndian.PutUint16(icmp[6:], seq)
	copy(icmp[8:], payload)

	// ICMP checksum covers ICMP header + payload
	csum := Checksum(icmp[:8+len(payload)], 0)
	binary.BigEndian.PutUint16(icmp[2:], ^csum)
	return frame
}

func BuildICMPv6Echo(srcIP, dstIP netip.Addr, id, seq uint16, payload []byte, ttl uint8) []byte {
	// Non-standard: ICMPv6 Echo Request (type 128) over IPv4 header with protocol 58.
	icmpLen := 8 + len(payload)
	totalLen := 20 + icmpLen
	frame := make([]byte, totalLen)
	ip := BuildIPv4Header(uint16(totalLen), uint16(rand.Intn(65535)), ttl, 58, srcIP, dstIP)
	copy(frame, ip)

	icmp := frame[20:]
	icmp[0] = 128 // Echo Request
	icmp[1] = 0
	binary.BigEndian.PutUint16(icmp[4:], id)
	binary.BigEndian.PutUint16(icmp[6:], seq)
	copy(icmp[8:], payload)

	// ICMPv6 checksum with IPv4 pseudo-header (protocol 58)
	pseudo := IPv4PseudoHeaderChecksum(srcIP, dstIP, 58, uint16(icmpLen))
	csum := Checksum(icmp[:icmpLen], pseudo)
	binary.BigEndian.PutUint16(icmp[2:], ^csum)
	return frame
}

func BuildRawUDP(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, payload []byte, ttl uint8) []byte {
	ipHdrLen := 20
	udpHdrLen := 8
	totalLen := ipHdrLen + udpHdrLen + len(payload)

	frame := make([]byte, totalLen)
	ip := BuildIPv4Header(uint16(totalLen), uint16(rand.Intn(65535)), ttl, 17, srcIP, dstIP)
	copy(frame, ip)

	udp := frame[ipHdrLen:]
	binary.BigEndian.PutUint16(udp[0:], srcPort)
	binary.BigEndian.PutUint16(udp[2:], dstPort)
	udpLen := uint16(udpHdrLen + len(payload))
	binary.BigEndian.PutUint16(udp[4:], udpLen)
	binary.BigEndian.PutUint16(udp[6:], 0) // checksum = 0 (optional in IPv4)

	if len(payload) > 0 {
		copy(frame[ipHdrLen+udpHdrLen:], payload)
	}

	return frame
}

func ParseSrcIP(buf []byte, isV6 bool) (netip.Addr, netip.Addr, bool) {
	if len(buf) < 20 {
		return netip.Addr{}, netip.Addr{}, false
	}
	if buf[0]>>4 != 4 {
		return netip.Addr{}, netip.Addr{}, false
	}
	src, _ := netip.AddrFromSlice(buf[12:16])
	dst, _ := netip.AddrFromSlice(buf[16:20])
	return src, dst, true
}

func ParseRawTCPPacket(buf []byte) (seq uint32, flags uint8, payload []byte, srcIP netip.Addr, dstIP netip.Addr, srcPort, dstPort uint16, ok bool) {
	if len(buf) < 40 {
		return
	}
	if buf[0]>>4 != 4 {
		return
	}
	ihl := (buf[0] & 0x0f) * 4
	if int(ihl) < 20 || int(ihl)+20 > len(buf) {
		return
	}
	if buf[9] != 6 {
		return
	}
	srcIP, _ = netip.AddrFromSlice(buf[12:16])
	dstIP, _ = netip.AddrFromSlice(buf[16:20])
	tcp := buf[ihl:]
	seq = binary.BigEndian.Uint32(tcp[4:])
	flags = tcp[13]
	srcPort = binary.BigEndian.Uint16(tcp[0:])
	dstPort = binary.BigEndian.Uint16(tcp[2:])
	do := int((tcp[12] >> 4) * 4)
	ihlInt := int(ihl)
	if do < 20 || ihlInt+do > len(buf) {
		return
	}
	payload = buf[ihlInt+do:]
	ok = true
	return
}

func ParseUDPPacket(buf []byte) (payload []byte, srcPort, dstPort uint16, ok bool) {
	if len(buf) < 28 {
		return
	}
	ihl := (buf[0] & 0x0f) * 4
	if int(ihl) < 20 {
		return
	}
	if buf[9] != 17 {
		return
	}
	udp := buf[ihl:]
	srcPort = binary.BigEndian.Uint16(udp[0:])
	dstPort = binary.BigEndian.Uint16(udp[2:])
	udpLen := int(binary.BigEndian.Uint16(udp[4:]))
	if udpLen < 8 || int(ihl)+udpLen > len(buf) {
		return
	}
	payload = udp[8:udpLen]
	ok = true
	return
}

func ParseICMPv4Echo(buf []byte) (id, seq uint16, payload []byte, ok bool) {
	if len(buf) < 28 {
		return
	}
	ihl := (buf[0] & 0x0f) * 4
	if int(ihl) < 20 {
		return
	}
	if buf[9] != 1 {
		return
	}
	icmp := buf[ihl:]
	if len(icmp) < 8 {
		return
	}
	if icmp[0] != 8 {
		return
	}
	id = binary.BigEndian.Uint16(icmp[4:])
	seq = binary.BigEndian.Uint16(icmp[6:])
	payload = icmp[8:]
	ok = true
	return
}

func ParseICMPv6Echo(buf []byte) (id, seq uint16, payload []byte, ok bool) {
	if len(buf) < 28 {
		return
	}
	var hdrLen int
	switch buf[0] >> 4 {
	case 4:
		if buf[9] != 58 {
			return
		}
		hdrLen = int(buf[0]&0x0f) * 4
	case 6:
		if buf[6] != 58 {
			return
		}
		hdrLen = 40
	default:
		return
	}
	if hdrLen < 20 || len(buf) < hdrLen+8 {
		return
	}
	icmp := buf[hdrLen:]
	if icmp[0] != 128 {
		return
	}
	id = binary.BigEndian.Uint16(icmp[4:])
	seq = binary.BigEndian.Uint16(icmp[6:])
	payload = icmp[8:]
	ok = true
	return
}
