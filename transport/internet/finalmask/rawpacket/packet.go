package rawpacket

import (
	"encoding/binary"
	"fmt"
	"net/netip"
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

func resolveSpoofPacketInfo(method Method, sendNext, receiveNext, timestamp uint32, tcpOptions, payload []byte) (spoofPacketInfo, error) {
	packetInfo := spoofPacketInfo{seqNum: sendNext, ackNum: receiveNext}
	switch method {
	case MethodWrongSequence:
		packetInfo.seqNum = sendNext - uint32(len(payload))
	case MethodWrongChecksum:
		packetInfo.corrupt = true
	case MethodWrongAcknowledgment:
		packetInfo.ackNum = receiveNext - uint32(defaultWindowSize/2)
	case MethodWrongMD5Sig:
		packetInfo.options = buildMD5SignatureOptions()
	case MethodWrongTimestamp:
		packetInfo.options = buildWrongTimestampOptions(timestamp, tcpOptions)
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

func buildWrongTimestampOptions(timestamp uint32, tcpOptions []byte) []byte {
	spoofedTimestamp := timestamp
	if spoofedTimestamp > tcpTimestampBackdate {
		spoofedTimestamp -= tcpTimestampBackdate
	} else {
		spoofedTimestamp = 0
	}
	if rewriteTCPOptionTimestamp(tcpOptions, spoofedTimestamp) {
		return tcpOptions
	}
	options := make([]byte, TCPOptionTSLength+2)
	EncodeTSOption(spoofedTimestamp, 0, options)
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
