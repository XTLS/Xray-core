package tun

import (
	"encoding/binary"
	"math/bits"
	"net/netip"
)

const (
	ipv4HeaderSize = 20
	ipv6HeaderSize = 40
	tcpHeaderSize  = 20
	udpHeaderSize  = 8

	protoICMPv4 = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
)

// packet is an IP packet with its header read
type packet struct {
	proto    byte
	src, dst netip.Addr
	// payload is what follows the IP header
	payload []byte
}

// parsePacket reads the IP header of b. Fragments are not accepted: what the system sends to the tun fits its MTU
func parsePacket(b []byte) (p packet, ok bool) {
	if len(b) < ipv4HeaderSize {
		return p, false
	}
	switch b[0] >> 4 {
	case 4:
		size := int(b[0]&0xf) * 4
		total := int(binary.BigEndian.Uint16(b[2:]))
		if size < ipv4HeaderSize || total < size || total > len(b) || binary.BigEndian.Uint16(b[6:])&0x3fff != 0 {
			return p, false
		}
		p.proto = b[9]
		p.src = netip.AddrFrom4([4]byte(b[12:16]))
		p.dst = netip.AddrFrom4([4]byte(b[16:20]))
		p.payload = b[size:total]
	case 6:
		if len(b) < ipv6HeaderSize {
			return p, false
		}
		total := ipv6HeaderSize + int(binary.BigEndian.Uint16(b[4:]))
		if total > len(b) {
			return p, false
		}
		p.proto = b[6]
		p.src = netip.AddrFrom16([16]byte(b[8:24]))
		p.dst = netip.AddrFrom16([16]byte(b[24:40]))
		p.payload = b[ipv6HeaderSize:total]
		// hop-by-hop options, routing, destination options
		for p.proto == 0 || p.proto == 43 || p.proto == 60 {
			if len(p.payload) < 8 {
				return p, false
			}
			size := int(p.payload[1])*8 + 8
			if size > len(p.payload) {
				return p, false
			}
			p.proto, p.payload = p.payload[0], p.payload[size:]
		}
	default:
		return p, false
	}
	return p, true
}

// putIPHeader writes the header of a packet from src to dst into b, without its length, and returns the size of the header
func putIPHeader(b []byte, proto byte, src, dst netip.Addr) int {
	if src.Is4() {
		s, d := src.As4(), dst.As4()
		clear(b[:ipv4HeaderSize])
		b[0] = 0x45
		if proto == protoTCP {
			b[6] = 0x40 // don't fragment
		}
		b[8] = 64
		b[9] = proto
		copy(b[12:], s[:])
		copy(b[16:], d[:])
		return ipv4HeaderSize
	}
	s, d := src.As16(), dst.As16()
	clear(b[:ipv6HeaderSize])
	b[0] = 0x60
	b[6] = proto
	b[7] = 64
	copy(b[8:], s[:])
	copy(b[24:], d[:])
	return ipv6HeaderSize
}

// setIPLength completes the header ip of a packet that is size bytes long with it
func setIPLength(ip []byte, size int) {
	if len(ip) == ipv4HeaderSize {
		binary.BigEndian.PutUint16(ip[2:], uint16(size))
		ip[10], ip[11] = 0, 0
		binary.BigEndian.PutUint16(ip[10:], checksum(sum(ip, 0)))
		return
	}
	binary.BigEndian.PutUint16(ip[4:], uint16(size-ipv6HeaderSize))
}

// transportChecksum is the checksum of a TCP or UDP segment, header and payload, of a packet with the header ip.
// The checksum field of header is zero
func transportChecksum(ip []byte, proto byte, header, payload []byte) uint16 {
	return checksum(sum(payload, sum(header, pseudoSum(ip, proto, len(header)+len(payload)))))
}

// pseudoSum is what the header ip of a packet adds to the checksum of its TCP or UDP segment of size bytes
func pseudoSum(ip []byte, proto byte, size int) uint64 {
	addresses := ip[12:ipv4HeaderSize]
	if len(ip) == ipv6HeaderSize {
		addresses = ip[8:]
	}
	return sum(addresses, uint64(proto)+uint64(size))
}

// sum adds the 16-bit words of b to s, with the carry of every addition added back
func sum(b []byte, s uint64) uint64 {
	var c uint64
	for len(b) >= 32 {
		s, c = bits.Add64(s, binary.BigEndian.Uint64(b), c)
		s, c = bits.Add64(s, binary.BigEndian.Uint64(b[8:]), c)
		s, c = bits.Add64(s, binary.BigEndian.Uint64(b[16:]), c)
		s, c = bits.Add64(s, binary.BigEndian.Uint64(b[24:]), c)
		b = b[32:]
	}
	for len(b) >= 8 {
		s, c = bits.Add64(s, binary.BigEndian.Uint64(b), c)
		b = b[8:]
	}
	if len(b) >= 4 {
		s, c = bits.Add64(s, uint64(binary.BigEndian.Uint32(b)), c)
		b = b[4:]
	}
	if len(b) >= 2 {
		s, c = bits.Add64(s, uint64(binary.BigEndian.Uint16(b)), c)
		b = b[2:]
	}
	if len(b) == 1 {
		s, c = bits.Add64(s, uint64(b[0])<<8, c)
	}
	s, c = bits.Add64(s, 0, c)
	return s + c
}

// checksum folds s into the 16 bits that go into a header
func checksum(s uint64) uint16 {
	s = s>>32 + s&0xffffffff
	s = s>>16 + s&0xffff
	s = s>>16 + s&0xffff
	s = s>>16 + s&0xffff
	return ^uint16(s)
}
