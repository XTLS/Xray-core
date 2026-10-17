package tun

import (
	"encoding/binary"
	"math"
	"math/bits"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
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

	// the smallest that a link is believed to take whatever is said about it: what every IPv4 host takes,
	// and the smallest link that IPv6 runs on
	ipv4SmallestMTU = 576
	ipv6SmallestMTU = 1280

	// the header that an IPv6 packet has in front of each of its fragments, and its number
	fragmentHeaderSize = 8
	protoFragment      = 44
	// fragmentsMost is how many packets can be waiting for the rest of their fragments,
	// fragmentsTime how long they are waited for at most
	fragmentsMost = 64
	fragmentsTime = 30 * time.Second
)

// packet is an IP packet with its header read
type packet struct {
	proto    byte
	src, dst netip.Addr
	// payload is what follows the IP header, without the last rest bytes of it when they are in other buffers
	payload []byte
	rest    int
	// fragment is set if payload is a part of what follows the IP header: the one at offset of the packet
	// with the number id, which has more after it or not
	fragment bool
	more     bool
	offset   int
	id       uint32
}

// parsePacket reads the IP header of a packet that is b and rest bytes after it
func parsePacket(b []byte, rest int) (p packet, ok bool) {
	if len(b) < ipv4HeaderSize {
		return p, false
	}
	switch b[0] >> 4 {
	case 4:
		size := int(b[0]&0xf) * 4
		total := int(binary.BigEndian.Uint16(b[2:]))
		if size < ipv4HeaderSize || total < size || total > len(b)+rest {
			return p, false
		}
		if f := binary.BigEndian.Uint16(b[6:]); f&0x3fff != 0 {
			p.fragment, p.more, p.offset, p.id = true, f&0x2000 != 0, int(f&0x1fff)*8, uint32(binary.BigEndian.Uint16(b[4:]))
		}
		p.proto = b[9]
		p.src = netip.AddrFrom4([4]byte(b[12:16]))
		p.dst = netip.AddrFrom4([4]byte(b[16:20]))
		p.payload, p.rest = b[size:min(total, len(b))], max(total-len(b), 0)
	case 6:
		if len(b) < ipv6HeaderSize {
			return p, false
		}
		total := ipv6HeaderSize + int(binary.BigEndian.Uint16(b[4:]))
		if total > len(b)+rest {
			return p, false
		}
		p.proto = b[6]
		p.src = netip.AddrFrom16([16]byte(b[8:24]))
		p.dst = netip.AddrFrom16([16]byte(b[24:40]))
		p.payload, p.rest = b[ipv6HeaderSize:min(total, len(b))], max(total-len(b), 0)
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
		if p.proto == protoFragment {
			f := p.payload
			if len(f) < fragmentHeaderSize {
				return p, false
			}
			p.fragment, p.more, p.offset, p.id = true, f[3]&1 != 0, int(binary.BigEndian.Uint16(f[2:])&^7), binary.BigEndian.Uint32(f[4:])
			p.proto, p.payload = f[0], f[fragmentHeaderSize:]
		}
	default:
		return p, false
	}
	return p, true
}

// verified reports whether the checksum of what the packet carries is right
func (p packet) verified() bool {
	data := p.payload
	switch p.proto {
	case protoICMPv4:
		return checksum(sum(data, 0)) == 0
	case protoUDP:
		if len(data) < udpHeaderSize {
			return false
		}
		// the packet may be longer than what it carries
		size := int(binary.BigEndian.Uint16(data[4:]))
		if size < udpHeaderSize || size > len(data) {
			return false
		}
		if p.src.Is4() && data[6]|data[7] == 0 {
			// zero stands for no checksum
			return true
		}
		data = data[:size]
	case protoTCP, protoICMPv6:
	default:
		return true
	}
	pseudo := uint64(p.proto) + uint64(len(data))
	if p.src.Is4() {
		src, dst := p.src.As4(), p.dst.As4()
		pseudo = sum(dst[:], sum(src[:], pseudo))
	} else {
		src, dst := p.src.As16(), p.dst.As16()
		pseudo = sum(dst[:], sum(src[:], pseudo))
	}
	return checksum(sum(data, pseudo)) == 0
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

// writeFragments writes a packet that is larger than mtu to tun in fragments that are not. header is its IP header
// with what follows that up to payload, which is no more than the header of a UDP packet. id is the number
// of the packet if it is an IPv6 one
func writeFragments(tun Tun, mtu int, id uint32, header, payload []byte) error {
	var b [ipv6HeaderSize + fragmentHeaderSize + udpHeaderSize]byte
	size := ipv4HeaderSize
	if header[0]>>4 == 6 {
		size = ipv6HeaderSize
	}
	n := copy(b[:], header[:size])
	if size == ipv6HeaderSize {
		// the number goes into a header of its own, behind the IP header. That of IPv4 has it
		b[6], b[n] = protoFragment, header[6]
		binary.BigEndian.PutUint32(b[n+4:], id)
		n += fragmentHeaderSize
	}
	// first goes in front of payload, in the first fragment
	first := header[size:]
	if n+len(first) > len(b) {
		return errors.New("no room for a header of ", len(first), " bytes in a fragment")
	}
	// every fragment but the last is a number of 8 bytes
	room, total := (mtu-n)&^7, len(first)+len(payload)
	if room < 8 {
		return errors.New("no room for a fragment in an MTU of ", mtu)
	}
	for offset := 0; offset < total; {
		h, part := b[:n], min(room, total-offset)
		last := offset+part == total
		if size == ipv6HeaderSize {
			f := uint16(offset)
			if !last {
				f |= 1
			}
			binary.BigEndian.PutUint16(b[size+2:], f)
		} else {
			f := uint16(offset / 8)
			if !last {
				f |= 0x2000
			}
			binary.BigEndian.PutUint16(b[6:], f)
		}
		setIPLength(b[:size], n+part)
		data := payload[max(offset-len(first), 0):min(offset+part-len(first), len(payload))]
		if offset == 0 {
			h = b[:n+copy(b[n:], first)]
		}
		if err := tun.WritePacket(h, data); err != nil {
			return err
		}
		offset += part
	}
	return nil
}

// fragmented is a packet of which not every fragment has come yet
type fragmented struct {
	// data is what follows its IP header, as far as its last fragment that has come goes
	data []byte
	// parts are what of data has come, in order and apart from each other
	parts [][2]int
	// size is that of data when all of it has come, known from the last fragment
	size  int
	known bool
	since time.Time
}

// reassembly puts the packets that come in fragments together
type reassembly struct {
	mu      sync.Mutex
	packets map[fragments]*fragmented
}

// fragments is what the fragments of a packet have in common
type fragments struct {
	src, dst netip.Addr
	proto    byte
	id       uint32
}

// add takes the fragment p of a packet. With the last one that was missing, it returns the packet.
// A packet whose fragments do not fit each other is given up
func (r *reassembly) add(p packet) (packet, bool) {
	fragment, offset, end := p.payload, p.offset, p.offset+len(p.payload)
	// what an IP packet can carry
	most := math.MaxUint16
	if p.src.Is4() {
		most -= ipv4HeaderSize
	}
	if len(fragment) == 0 || end > most || p.more && len(fragment)%8 != 0 {
		return p, false
	}
	key, now := fragments{p.src, p.dst, p.proto, p.id}, time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.packets[key]
	if f != nil && now.Sub(f.since) > fragmentsTime {
		// what is left of a packet whose other fragments were lost: this is one of another packet with its number
		f = nil
	}
	if f == nil {
		if _, stale := r.packets[key]; !stale && len(r.packets) >= fragmentsMost {
			// the one that is waited for the longest makes room, not the one that comes now
			var longest fragments
			var since time.Time
			for other, old := range r.packets {
				if since.IsZero() || old.since.Before(since) {
					longest, since = other, old.since
				}
			}
			delete(r.packets, longest)
		}
		if r.packets == nil {
			r.packets = make(map[fragments]*fragmented)
		}
		f = &fragmented{since: now}
		r.packets[key] = f
	}
	for _, part := range f.parts {
		if offset >= part[0] && end <= part[1] {
			// came already
			return p, false
		}
		if offset < part[1] && part[0] < end {
			// fragments of one packet do not overlap: these are of two, or made to be taken for something else
			delete(r.packets, key)
			return p, false
		}
	}
	if f.known && end > f.size || !p.more && len(f.data) > end {
		// past its end, or an end before what came
		delete(r.packets, key)
		return p, false
	}
	if !p.more {
		f.size, f.known = end, true
	}
	if len(f.data) < end {
		f.data = append(f.data, make([]byte, end-len(f.data))...)
	}
	copy(f.data[offset:], fragment)
	i := 0
	for i < len(f.parts) && f.parts[i][1] < offset {
		i++
	}
	j := i
	for ; j < len(f.parts) && f.parts[j][0] <= end; j++ {
		offset, end = min(offset, f.parts[j][0]), max(end, f.parts[j][1])
	}
	f.parts = slices.Replace(f.parts, i, j, [2]int{offset, end})
	if !f.known || f.parts[0] != [2]int{0, f.size} {
		return p, false
	}
	delete(r.packets, key)
	p.payload, p.fragment = f.data[:f.size], false
	return p, true
}
