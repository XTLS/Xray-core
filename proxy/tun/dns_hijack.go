package tun

import (
	"encoding/binary"
	"net/netip"
	"time"
)

type DNSHijackOptions struct {
	Mode              string
	DNSAddresses      []netip.Addr
	LoopbackAddresses []netip.Addr
	TUNAddresses      []netip.Addr
	Writer            func([]byte) error
	UDPTimeout        time.Duration
}

type DNSHijacker struct {
	opts DNSHijackOptions
}

func NewDNSHijacker(opts DNSHijackOptions) *DNSHijacker {
	return &DNSHijacker{opts: opts}
}

func (h *DNSHijacker) Process(packet []byte) (bool, error) {
	if h.opts.Mode != "hijack" {
		return false, nil
	}

	if len(packet) < 20 {
		return false, nil
	}

	version := packet[0] >> 4
	var srcIP, dstIP netip.Addr
	var srcPort, dstPort uint16
	var payloadOffset int

	switch version {
	case 4:
		ihl := int(packet[0] & 0x0F)
		if ihl < 5 {
			return false, nil
		}
		payloadOffset = ihl * 4
		if len(packet) < payloadOffset+8 {
			return false, nil
		}
		srcIP = netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]})
		dstIP = netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
		proto := packet[9]
		if proto != 17 {
			return false, nil
		}
	case 6:
		if len(packet) < 48 {
			return false, nil
		}
		srcIP = netip.AddrFrom16([16]byte(packet[8:24]))
		dstIP = netip.AddrFrom16([16]byte(packet[24:40]))
		nextHdr := packet[6]
		if nextHdr != 17 {
			return false, nil
		}
		payloadOffset = 40
	default:
		return false, nil
	}

	udpHdr := packet[payloadOffset:]
	if len(udpHdr) < 8 {
		return false, nil
	}
	srcPort = binary.BigEndian.Uint16(udpHdr[0:2])
	dstPort = binary.BigEndian.Uint16(udpHdr[2:4])

	if dstPort != 53 {
		return false, nil
	}

	isLoopback := false
	for _, lb := range h.opts.LoopbackAddresses {
		if dstIP == lb {
			isLoopback = true
			break
		}
	}

	isDNSAddr := false
	for _, dns := range h.opts.DNSAddresses {
		if dstIP == dns {
			isDNSAddr = true
			break
		}
	}

	if !isLoopback && !isDNSAddr {
		return false, nil
	}

	return h.handleDNSQuery(packet, srcIP, srcPort, dstIP, dstPort, packet[payloadOffset+8:])
}

func (h *DNSHijacker) handleDNSQuery(origPacket []byte, srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16, query []byte) (bool, error) {
	return true, nil
}
