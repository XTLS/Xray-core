package wireguard

import (
	"context"

	"github.com/xtls/xray-core/common/errors"
	tunicmp "github.com/xtls/xray-core/proxy/tun/icmp"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
)

// CreateICMPEchoResponder answers ICMP echo requests from peers locally, the way
// the TUN inbound does: ICMP is not proxied, but ping and connectivity checks
// through the tunnel get a reply instead of timing out.
//
// In promiscuous mode gVisor skips its own IPv4 echo reply for addresses that are
// not assigned to the NIC and leaves it to a custom handler; IPv6 is registered
// too so both families behave the same.
func CreateICMPEchoResponder(gstack *stack.Stack) {
	gstack.SetTransportProtocolHandler(icmp.ProtocolNumber4, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		return handleICMPEcho(gstack, header.IPv4ProtocolNumber, id, pkt)
	})
	gstack.SetTransportProtocolHandler(icmp.ProtocolNumber6, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		return handleICMPEcho(gstack, header.IPv6ProtocolNumber, id, pkt)
	})
}

func handleICMPEcho(gstack *stack.Stack, netProto tcpip.NetworkProtocolNumber, id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	srcIP := id.RemoteAddress
	dstIP := id.LocalAddress
	if srcIP.Len() == 0 || dstIP.Len() == 0 {
		return true
	}

	headerBytes := pkt.TransportHeader().Slice()
	payloadBytes := pkt.Data().AsRange().ToSlice()
	message := make([]byte, len(headerBytes)+len(payloadBytes))
	copy(message, headerBytes)
	copy(message[len(headerBytes):], payloadBytes)

	if _, _, ok := tunicmp.ParseEchoRequest(netProto, message); !ok {
		return true
	}

	reply, err := tunicmp.BuildLocalEchoReply(netProto, message, dstIP, srcIP)
	if err != nil {
		errors.LogInfoInner(context.Background(), err, "failed to build local icmp echo reply")
		return true
	}
	if err := writeRawICMPPacket(gstack, netProto, reply, dstIP, srcIP); err != nil {
		errors.LogInfoInner(context.Background(), err, "failed to write local icmp echo reply")
	}
	return true
}

func writeRawICMPPacket(gstack *stack.Stack, netProto tcpip.NetworkProtocolNumber, message []byte, srcIP, dstIP tcpip.Address) error {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.IPv6MinimumSize,
		Payload:            buffer.MakeWithData(message),
	})
	defer pkt.DecRef()

	if netProto == header.IPv4ProtocolNumber {
		ipHdr := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
		ipHdr.Encode(&header.IPv4Fields{
			TotalLength: uint16(header.IPv4MinimumSize + len(message)),
			TTL:         64,
			Protocol:    uint8(header.ICMPv4ProtocolNumber),
			SrcAddr:     srcIP,
			DstAddr:     dstIP,
		})
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	} else {
		ipHdr := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
		ipHdr.Encode(&header.IPv6Fields{
			PayloadLength:     uint16(len(message)),
			TransportProtocol: header.ICMPv6ProtocolNumber,
			HopLimit:          64,
			SrcAddr:           srcIP,
			DstAddr:           dstIP,
		})
	}

	if err := gstack.WriteRawPacket(1, netProto, buffer.MakeWithView(pkt.ToView())); err != nil {
		return errors.New("failed to write raw icmp packet back to stack ", err)
	}
	return nil
}
