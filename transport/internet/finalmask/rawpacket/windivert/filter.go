package windivert

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// WINDIVERT_FILTER VM instruction layout (24 bytes, #pragma pack(1)):
//
//	word 0 (LE):  field:11 | test:5 | success:16
//	word 1 (LE):  failure:16 | neg:1 | reserved:15
//	words 2..5:   arg[4] (native-endian uint32 each)
//
// The driver walks this as a decision tree: evaluate the test at inst i;
// on success jump to success; on failure jump to failure. Continuations
// 0x7FFE and 0x7FFF are ACCEPT and REJECT terminals.
const (
	filterInstBytes = 24
	filterMaxInsts  = 256

	fieldZero        = 0
	fieldOutbound    = 2
	fieldIP          = 5
	fieldIPv6        = 6
	fieldTCP         = 8
	fieldIPSrcAddr   = 21
	fieldIPDstAddr   = 22
	fieldIPv6SrcAddr = 28
	fieldIPv6DstAddr = 29
	fieldTCPSrcPort  = 38
	fieldTCPDstPort  = 39

	testEQ = 0

	resultAccept uint16 = 0x7FFE
	resultReject uint16 = 0x7FFF
)

// Filter flags passed to IOCTL_WINDIVERT_STARTUP alongside the compiled
// filter. These tell the driver what *kinds* of packets the filter might
// match, used as a kernel-side fast-reject.
const (
	filterFlagOutbound uint64 = 0x0020
	filterFlagIP       uint64 = 0x0040
	filterFlagIPv6     uint64 = 0x0080
)

type filterInst struct {
	field   uint16 // 11 bits used
	test    uint8  //  5 bits used
	success uint16
	failure uint16
	neg     bool
	arg     [4]uint32
}

// Filter is a typed specification of packets to capture. It replaces
// WinDivert's filter string language.
//
// Zero value = "reject all" (match nothing), suitable for send-only handles.
type Filter struct {
	insts []filterInst
	flags uint64 // filter flags for STARTUP ioctl
}

// reject returns a filter that matches no packet. The empty insts slice
// is encoded as a single rejecting instruction by encode().
func reject() *Filter {
	return &Filter{}
}

// OutboundTCP returns a filter matching outbound TCP packets on the given
// 5-tuple. Both addresses must share an address family (IPv4 or IPv6).
func OutboundTCP(src, dst netip.AddrPort) (*Filter, error) {
	return tcpFilter(src, dst, true)
}

// BidirectionalTCP returns a filter matching TCP packets in either direction
// on the given 5-tuple. Both addresses must share an address family.
func BidirectionalTCP(src, dst netip.AddrPort) (*Filter, error) {
	return tcpFilter(src, dst, false)
}

func tcpFilter(src, dst netip.AddrPort, outboundOnly bool) (*Filter, error) {
	if !src.IsValid() || !dst.IsValid() {
		return nil, errors.New("windivert: filter: invalid address port")
	}
	if src.Addr().Is4() != dst.Addr().Is4() {
		return nil, errors.New("windivert: filter: mixed IPv4/IPv6")
	}
	f := &Filter{}
	if outboundOnly {
		f.flags = filterFlagOutbound
		f.add(fieldOutbound, testEQ, argUint32(1))
	}
	if src.Addr().Is4() {
		f.flags |= filterFlagIP
		f.add(fieldIP, testEQ, argUint32(1))
		f.add(fieldTCP, testEQ, argUint32(1))
		f.add(fieldIPSrcAddr, testEQ, argIPv4(src.Addr()))
		f.add(fieldIPDstAddr, testEQ, argIPv4(dst.Addr()))
	} else {
		f.flags |= filterFlagIPv6
		f.add(fieldIPv6, testEQ, argUint32(1))
		f.add(fieldTCP, testEQ, argUint32(1))
		f.add(fieldIPv6SrcAddr, testEQ, argIPv6(src.Addr()))
		f.add(fieldIPv6DstAddr, testEQ, argIPv6(dst.Addr()))
	}
	f.add(fieldTCPSrcPort, testEQ, argUint32(uint32(src.Port())))
	f.add(fieldTCPDstPort, testEQ, argUint32(uint32(dst.Port())))
	return f, nil
}

func (f *Filter) add(field uint16, test uint8, arg [4]uint32) {
	f.insts = append(f.insts, filterInst{field: field, test: test, arg: arg})
}

func argUint32(v uint32) [4]uint32 { return [4]uint32{v, 0, 0, 0} }

// argIPv4 encodes an IPv4 address for IP_SRCADDR/IP_DSTADDR. The driver
// compares against an IPv4-mapped-IPv6 form: {host_order_u32, 0x0000FFFF,
// 0, 0} (see sys/windivert.c windivert_get_ipv4_addr and the IPv4_SRCADDR
// val-word construction). Omitting the 0x0000FFFF marker causes the EQ
// test to fail for every packet.
func argIPv4(addr netip.Addr) [4]uint32 {
	b := addr.As4()
	return [4]uint32{binary.BigEndian.Uint32(b[:]), 0x0000FFFF, 0, 0}
}

// argIPv6 encodes an IPv6 address for IPV6_SRCADDR/IPV6_DSTADDR. The
// driver stores the address as four host-order uint32s in REVERSED word
// order: val[0]=low (bytes 12..15), val[3]=high (bytes 0..3). See
// sys/windivert.c windivert_outbound_network_v6_classify val-word
// construction.
func argIPv6(addr netip.Addr) [4]uint32 {
	b := addr.As16()
	return [4]uint32{
		binary.BigEndian.Uint32(b[12:16]),
		binary.BigEndian.Uint32(b[8:12]),
		binary.BigEndian.Uint32(b[4:8]),
		binary.BigEndian.Uint32(b[0:4]),
	}
}

// encode serializes the Filter to the on-wire WINDIVERT_FILTER[] format
// plus the filter_flags for STARTUP ioctl.
func (f *Filter) encode() ([]byte, uint64, error) {
	if len(f.insts) == 0 {
		// "Reject all" — one instruction, ZERO == 0 is always true, but we
		// invert by setting both success and failure to REJECT.
		return encodeInst(filterInst{
			field:   fieldZero,
			test:    testEQ,
			success: resultReject,
			failure: resultReject,
		}), 0, nil
	}
	if len(f.insts) > filterMaxInsts-1 {
		return nil, 0, errors.New("windivert: filter too long")
	}
	buf := make([]byte, 0, filterInstBytes*len(f.insts))
	for i, inst := range f.insts {
		if i == len(f.insts)-1 {
			inst.success = resultAccept
		} else {
			inst.success = uint16(i + 1)
		}
		inst.failure = resultReject
		buf = append(buf, encodeInst(inst)...)
	}
	return buf, f.flags, nil
}

func encodeInst(inst filterInst) []byte {
	out := make([]byte, filterInstBytes)
	word0 := uint32(inst.field&0x7FF) | uint32(inst.test&0x1F)<<11 |
		uint32(inst.success)<<16
	word1 := uint32(inst.failure)
	if inst.neg {
		word1 |= 1 << 16
	}
	binary.LittleEndian.PutUint32(out[0:4], word0)
	binary.LittleEndian.PutUint32(out[4:8], word1)
	binary.LittleEndian.PutUint32(out[8:12], inst.arg[0])
	binary.LittleEndian.PutUint32(out[12:16], inst.arg[1])
	binary.LittleEndian.PutUint32(out[16:20], inst.arg[2])
	binary.LittleEndian.PutUint32(out[20:24], inst.arg[3])
	return out
}
