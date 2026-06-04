package rawpacket

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

const (
	defaultWindowSize uint16 = 0xFFFF
	tcpHeaderLen             = TCPMinimumSize

	tcpOptionMD5Signature       = 19
	tcpOptionMD5SignatureLength = 18
	tcpTimestampBackdate        = 3600000
)

type spoofPacketInfo struct {
	seqNum  uint32
	ackNum  uint32
	corrupt bool
	options []byte
}

func buildTCPSegment(
	src netip.AddrPort,
	dst netip.AddrPort,
	packetInfo spoofPacketInfo,
	payload []byte,
	ttl uint8,
) []byte {
	if src.Addr().Is4() != dst.Addr().Is4() {
		panic("rawpacket: mixed IPv4/IPv6 address family")
	}
	var (
		frame       []byte
		ipHeaderLen int
	)
	ipPayloadLen := tcpHeaderLen + len(packetInfo.options) + len(payload)
	if src.Addr().Is4() {
		ipHeaderLen = IPv4MinimumSize
		frame = make([]byte, ipHeaderLen+ipPayloadLen)
		ip := IPv4(frame[:ipHeaderLen])
		ip.Encode(uint16(len(frame)), 0, ttl, TCPProtocolNumber, src.Addr(), dst.Addr())
	} else {
		ipHeaderLen = IPv6MinimumSize
		frame = make([]byte, ipHeaderLen+ipPayloadLen)
		ip := IPv6(frame[:ipHeaderLen])
		ip.Encode(uint16(ipPayloadLen), TCPProtocolNumber, ttl, src.Addr(), dst.Addr())
	}
	encodeTCP(frame, ipHeaderLen, src, dst, packetInfo, payload)
	return frame
}

func encodeTCP(frame []byte, ipHeaderLen int, src, dst netip.AddrPort, packetInfo spoofPacketInfo, payload []byte) {
	tcp := TCP(frame[ipHeaderLen:])
	copy(frame[ipHeaderLen+tcpHeaderLen:], packetInfo.options)
	optionsLen := len(packetInfo.options)
	copy(frame[ipHeaderLen+tcpHeaderLen+optionsLen:], payload)
	tcp.Encode(src.Port(), dst.Port(), packetInfo.seqNum, packetInfo.ackNum, uint8(tcpHeaderLen+optionsLen), TCPFlagAck|TCPFlagPsh, defaultWindowSize)
	applyTCPChecksum(tcp, src.Addr(), dst.Addr(), payload, packetInfo.corrupt)
}

func buildSpoofFrame(method Method, src, dst netip.AddrPort, sendNext, receiveNext, timestamp uint32, tcpOptions, payload []byte, ttl uint8) ([]byte, error) {
	packetInfo, err := resolveSpoofPacketInfo(method, sendNext, receiveNext, timestamp, tcpOptions, payload)
	if err != nil {
		return nil, err
	}
	return buildTCPSegment(src, dst, packetInfo, payload, ttl), nil
}

// buildSpoofTCPSegment returns a TCP segment without an IP header, for
// platforms where the kernel synthesises the IP header (darwin IPv6).
func buildSpoofTCPSegment(method Method, src, dst netip.AddrPort, sendNext, receiveNext, timestamp uint32, payload []byte) ([]byte, error) {
	packetInfo, err := resolveSpoofPacketInfo(method, sendNext, receiveNext, timestamp, nil, payload)
	if err != nil {
		return nil, err
	}
	segment := make([]byte, tcpHeaderLen+len(packetInfo.options)+len(payload))
	encodeTCP(segment, 0, src, dst, packetInfo, payload)
	return segment, nil
}

func buildTimestampOption(tsVal, tsEcr uint32) []byte {
	b := make([]byte, TCPOptionTSLength+2)
	EncodeTSOption(tsVal, tsEcr, b)
	return b
}

func resolveSpoofPacketInfo(method Method, sendNext, receiveNext, timestamp uint32, tcpOptions, payload []byte) (spoofPacketInfo, error) {
	packetInfo := spoofPacketInfo{seqNum: sendNext, ackNum: receiveNext}
	// Always include a valid TCP timestamp option in all methods.
	// Modern TCP connections always carry timestamps. A segment without
	// them is immediately flagged as anomalous by DPI equipment.
	tsVal := timestamp
	if tsVal == 0 {
		tsVal = uint32(time.Now().UnixMilli())
	}
	packetInfo.seqNum = sendNext - uint32(len(payload))
	tsOpt := buildTimestampOption(tsVal, 0)
	switch method {
	case MethodWrongSequence:
		packetInfo.options = tsOpt
	case MethodWrongChecksum:
		packetInfo.corrupt = true
		packetInfo.options = tsOpt
	case MethodWrongAcknowledgment:
		packetInfo.ackNum = receiveNext - uint32(defaultWindowSize/2)
		packetInfo.options = tsOpt
	case MethodWrongMD5Sig:
		md5Opt := buildMD5SignatureOptions()
		combined := make([]byte, 0, len(tsOpt)+2+len(md5Opt))
		combined = append(combined, tsOpt...)
		combined = append(combined, TCPOptionNOP, TCPOptionNOP)
		combined = append(combined, md5Opt...)
		packetInfo.options = combined
	case MethodWrongTimestamp:
		backdated := tsVal
		if backdated > tcpTimestampBackdate {
			backdated -= tcpTimestampBackdate
		} else {
			backdated = 0
		}
		if rewriteTCPOptionTimestamp(tcpOptions, backdated) {
			packetInfo.options = tcpOptions
		} else {
			packetInfo.options = buildTimestampOption(backdated, 0)
		}
	default:
		return packetInfo, fmt.Errorf("rawpacket: unknown method %v", method)
	}
	return packetInfo, nil
}

func buildMD5SignatureOptions() []byte {
	options := make([]byte, tcpOptionMD5SignatureLength+2)
	options[0] = tcpOptionMD5Signature
	options[1] = tcpOptionMD5SignatureLength
	return options
}

// rewriteTCPOptionTimestamp finds the TS option in tcpOptions and writes
// timestamp into its TSVal field in place. The caller must own tcpOptions
// (parseTCPPacket already returns a private copy on Windows).
func rewriteTCPOptionTimestamp(tcpOptions []byte, timestamp uint32) bool {
	for i := 0; i < len(tcpOptions); {
		switch tcpOptions[i] {
		case TCPOptionEOL:
			return false
		case TCPOptionNOP:
			i++
			continue
		}
		if i+1 >= len(tcpOptions) {
			return false
		}
		optionLen := int(tcpOptions[i+1])
		if optionLen < 2 || i+optionLen > len(tcpOptions) {
			return false
		}
		if tcpOptions[i] == TCPOptionTS && optionLen == TCPOptionTSLength {
			binary.BigEndian.PutUint32(tcpOptions[i+2:], timestamp)
			return true
		}
		i += optionLen
	}
	return false
}

// buildSpoofFromCapturedPacket takes a captured IP+TCP packet and builds a
// spoofed version that preserves the real connection's TCP options, IP ID
// sequencing, and window size.
func buildSpoofFromCapturedPacket(captured []byte, isV6 bool, synSeq uint32, fakePayload []byte, method Method) ([]byte, error) {
	var ipHdrLen int
	var srcAddr, dstAddr netip.Addr

	if isV6 {
		if len(captured) < IPv6MinimumSize+TCPMinimumSize {
			return nil, errors.New("rawpacket: captured packet too short for IPv6")
		}
		ip := IPv6(captured)
		if ip.TransportProtocol() != TCPProtocolNumber {
			return nil, errors.New("rawpacket: captured packet is not TCP")
		}
		ipHdrLen = IPv6MinimumSize
		srcAddr = ip.Src()
		dstAddr = ip.Dst()
	} else {
		if len(captured) < IPv4MinimumSize+TCPMinimumSize {
			return nil, errors.New("rawpacket: captured packet too short for IPv4")
		}
		ip := IPv4(captured)
		if ip.Protocol() != TCPProtocolNumber {
			return nil, errors.New("rawpacket: captured packet is not TCP")
		}
		ipHdrLen = int(ip.HeaderLength())
		if ipHdrLen < IPv4MinimumSize || ipHdrLen > len(captured) {
			return nil, fmt.Errorf("rawpacket: invalid IPv4 header length %d", ipHdrLen)
		}
		srcAddr = ip.Src()
		dstAddr = ip.Dst()
	}

	if ipHdrLen+TCPMinimumSize > len(captured) {
		return nil, errors.New("rawpacket: captured packet truncated")
	}

	tcp := TCP(captured[ipHdrLen:])
	tcpHdrLen := int(tcp.DataOffset())
	if tcpHdrLen < TCPMinimumSize || ipHdrLen+tcpHdrLen > len(captured) {
		return nil, fmt.Errorf("rawpacket: invalid TCP header length %d in captured packet", tcpHdrLen)
	}

	capturedAck := tcp.AckNumber()
	capturedFlags := tcp.Flags()

	// Preserve captured TCP options (timestamp, SACK, window scale, etc.)
	// We work on a copy, not the original.
	tcpOpts := make([]byte, tcpHdrLen-TCPMinimumSize)
	copy(tcpOpts, tcp.Options())

	// Determine captured total length
	var totalLen int
	if isV6 {
		totalLen = ipHdrLen + int(IPv6(captured).PayloadLength())
	} else {
		totalLen = int(IPv4(captured).TotalLength())
	}
	if totalLen > len(captured) {
		totalLen = len(captured)
	}
	originalPayloadLen := totalLen - ipHdrLen - tcpHdrLen
	if originalPayloadLen < 0 {
		originalPayloadLen = 0
	}

	// Allocate output: IP hdr + TCP hdr (with copied options) + fake payload
	newTotalLen := ipHdrLen + tcpHdrLen + len(fakePayload)
	out := make([]byte, newTotalLen)

	// Copy IP header
	copy(out[:ipHdrLen], captured[:ipHdrLen])

	// Copy TCP header + options (original payload is NOT copied)
	copy(out[ipHdrLen:ipHdrLen+tcpHdrLen], captured[ipHdrLen:ipHdrLen+tcpHdrLen])

	// Write fake payload
	copy(out[ipHdrLen+tcpHdrLen:], fakePayload)

	// --- Modify IP header ---
	if isV6 {
		ip6 := IPv6(out)
		ip6.SetPayloadLength(uint16(tcpHdrLen + len(fakePayload)))
	} else {
		ip4 := IPv4(out)
		ip4.SetTotalLength(uint16(newTotalLen))
		// Increment IP ID by 1 to maintain sequential appearance
		ip4.SetID(ip4.ID() + 1)
		ip4.RecalcChecksum()
	}

	// --- Modify TCP header ---
	tcpOut := TCP(out[ipHdrLen:])

	// Always use before-window seq so the server drops the fake packet.
	// All methods apply this; method-specific corruption is applied on top.
	newSeq := (synSeq + 1 - uint32(len(fakePayload))) & 0xffffffff
	tcpOut.SetSequenceNumber(newSeq)

	if method == MethodWrongAcknowledgment {
		tcpOut.SetAckNumber(capturedAck - uint32(defaultWindowSize/2))
	}

	// Backdate timestamp for wrong-timestamp method
	if method == MethodWrongTimestamp {
		opts := tcpOut.Options()
		tsSlice := make([]byte, len(opts))
		copy(tsSlice, opts)
		if tsVal, hasTS := ParseTCPOptions(tsSlice); hasTS {
			backdated := tsVal
			if backdated > tcpTimestampBackdate {
				backdated -= tcpTimestampBackdate
			} else {
				backdated = 0
			}
			rewriteTCPOptionTimestamp(opts, backdated)
		}
	}

	// Set PSH flag since the spoofed packet is a data segment
	tcpOut.SetFlags(capturedFlags | TCPFlagPsh)

	// Recalculate TCP checksum
	tcpOut.SetChecksum(0)
	tcpLen := tcpHdrLen + len(fakePayload)
	pseudo := PseudoHeaderChecksum(TCPProtocolNumber, srcAddr.AsSlice(), dstAddr.AsSlice(), uint16(tcpLen))
	tcpChecksum := ^tcpOut.CalculateChecksum(pseudo)

	// Apply checksum corruption for wrong-checksum method
	if method == MethodWrongChecksum {
		tcpChecksum ^= 0xFFFF
	}
	tcpOut.SetChecksum(tcpChecksum)

	return out, nil
}

func applyTCPChecksum(tcp TCP, srcAddr, dstAddr netip.Addr, payload []byte, corrupt bool) {
	tcpLen := int(tcp.DataOffset()) + len(payload)
	pseudo := PseudoHeaderChecksum(TCPProtocolNumber, srcAddr.AsSlice(), dstAddr.AsSlice(), uint16(tcpLen))
	payloadChecksum := Checksum(payload, 0)
	tcpChecksum := ^tcp.CalculateChecksum(CombineChecksum(pseudo, payloadChecksum))
	if corrupt {
		tcpChecksum ^= 0xFFFF
	}
	tcp.SetChecksum(tcpChecksum)
}
