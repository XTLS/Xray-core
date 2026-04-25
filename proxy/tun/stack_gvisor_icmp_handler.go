package tun

import (
	stdnet "net"
	"time"

	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	tunicmp "github.com/xtls/xray-core/proxy/tun/icmp"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const defaultICMPEchoTimeout = 30 * time.Second

func (t *stackGVisor) handleICMPv4Packet(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	return t.handleICMPEchoPacket(header.IPv4ProtocolNumber, id, pkt)
}

func (t *stackGVisor) handleICMPv6Packet(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	return t.handleICMPEchoPacket(header.IPv6ProtocolNumber, id, pkt)
}

func (t *stackGVisor) handleICMPEchoPacket(netProto tcpip.NetworkProtocolNumber, id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	srcIP := id.RemoteAddress
	dstIP := id.LocalAddress
	if srcIP.Len() == 0 || dstIP.Len() == 0 {
		return true
	}

	message := transportPacketBytes(pkt)
	ident, sequence, ok := tunicmp.ParseEchoRequest(netProto, message)
	if !ok {
		return true
	}

	errors.LogInfo(t.ctx, "[tun][icmp] ", tunicmp.ProtocolLabel(netProto), " echo request ", srcIP, " -> ", dstIP, " id=", ident, " seq=", sequence)

	go func() {
		if err := t.forwardICMPEcho(netProto, srcIP, dstIP, ident, sequence, message); err != nil {
			errors.LogInfoInner(t.ctx, err, "[tun] failed to proxy icmp echo")
		}
	}()

	return true
}

func (t *stackGVisor) forwardICMPEcho(netProto tcpip.NetworkProtocolNumber, srcIP, dstIP tcpip.Address, ident, sequence uint16, message []byte) error {
	timeout := t.icmpEchoTimeout()
	socket, err := tunicmp.OpenEchoSocket(netProto, dstIP)
	if err != nil {
		return errors.New("listen icmp socket").Base(err)
	}
	defer socket.Conn.Close()

	if err := socket.Conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return errors.New("set icmp socket deadline").Base(err)
	}

	socketIdent, hasSocketIdent := socket.ReplyIdentifier()
	request, err := tunicmp.MarshalEchoMessage(netProto, true, ident, sequence, tunicmp.Payload(message))
	if err != nil {
		return errors.New("marshal icmp echo request").Base(err)
	}

	if _, err := socket.Conn.WriteTo(request, socket.RemoteAddr); err != nil {
		return errors.New("send icmp echo request to ", socket.RemoteAddr).Base(err)
	}

	replyBuf := make([]byte, 64<<10)
	var packetsRead int
	for {
		n, addr, err := socket.Conn.ReadFrom(replyBuf)
		if err != nil {
			return errors.New("read icmp echo reply after ", packetsRead, " packets").Base(err)
		}
		packetsRead++
		if !tunicmp.ReplyAddrMatches(addr, socket.RemoteAddr) {
			continue
		}

		reply := append([]byte(nil), replyBuf[:n]...)
		reply, err = tunicmp.NormalizeEchoReply(netProto, reply)
		if err != nil {
			return errors.New("normalize icmp echo reply from ", addr).Base(err)
		}
		replyIdent, ok := tunicmp.MatchEchoReply(netProto, reply, ident, sequence, socketIdent, hasSocketIdent)
		if !ok {
			continue
		}
		if tunicmp.IsDatagramNetwork(socket.Network) {
			isLocal, err := xnet.IsLocal(stdnet.IP(srcIP.AsSlice()))
			if err != nil {
				errors.LogInfoInner(t.ctx, err, "[tun][icmp] failed to determine whether source is local")
			} else if isLocal {
				errors.LogInfo(t.ctx, "[tun][icmp] ", tunicmp.ProtocolLabel(netProto), " echo reply handled by local stack, skipping tun injection id=", ident, " seq=", sequence, " socket=", socket.Network)
				return nil
			}
		}
		if replyIdent != ident {
			if err := tunicmp.RewriteEchoIdentifier(netProto, reply, ident); err != nil {
				return errors.New("rewrite icmp echo reply identifier").Base(err)
			}
		}
		if err := tunicmp.RewriteChecksum(netProto, reply, dstIP, srcIP); err != nil {
			return errors.New("rewrite icmp echo reply checksum").Base(err)
		}
		errors.LogInfo(t.ctx, "[tun][icmp] ", tunicmp.ProtocolLabel(netProto), " echo reply ", dstIP, " -> ", srcIP, " id=", ident, " seq=", sequence, " packetsRead=", packetsRead, " socket=", socket.Network)
		return t.writeRawICMPPacket(netProto, reply, dstIP, srcIP)
	}
}

func (t *stackGVisor) icmpEchoTimeout() time.Duration {
	timeout := t.idleTimeout
	if timeout <= 0 || timeout > defaultICMPEchoTimeout {
		return defaultICMPEchoTimeout
	}
	return timeout
}

func (t *stackGVisor) writeRawICMPPacket(netProto tcpip.NetworkProtocolNumber, message []byte, srcIP, dstIP tcpip.Address) error {
	ipHeaderSize := header.IPv6MinimumSize
	ipProtocol := header.IPv6ProtocolNumber
	transportProtocol := header.ICMPv6ProtocolNumber
	if netProto == header.IPv4ProtocolNumber {
		ipHeaderSize = header.IPv4MinimumSize
		ipProtocol = header.IPv4ProtocolNumber
		transportProtocol = header.ICMPv4ProtocolNumber
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: ipHeaderSize,
		Payload:            buffer.MakeWithData(message),
	})
	defer pkt.DecRef()

	if netProto == header.IPv4ProtocolNumber {
		ipHdr := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
		ipHdr.Encode(&header.IPv4Fields{
			TotalLength: uint16(header.IPv4MinimumSize + len(message)),
			TTL:         64,
			Protocol:    uint8(transportProtocol),
			SrcAddr:     srcIP,
			DstAddr:     dstIP,
		})
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	} else {
		ipHdr := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
		ipHdr.Encode(&header.IPv6Fields{
			PayloadLength:     uint16(len(message)),
			TransportProtocol: transportProtocol,
			HopLimit:          64,
			SrcAddr:           srcIP,
			DstAddr:           dstIP,
		})
	}

	if err := t.stack.WriteRawPacket(defaultNIC, ipProtocol, buffer.MakeWithView(pkt.ToView())); err != nil {
		return errors.New("failed to write raw icmp packet back to stack", err)
	}

	return nil
}

func transportPacketBytes(pkt *stack.PacketBuffer) []byte {
	headerBytes := pkt.TransportHeader().Slice()
	payloadBytes := pkt.Data().AsRange().ToSlice()
	message := make([]byte, len(headerBytes)+len(payloadBytes))
	copy(message, headerBytes)
	copy(message[len(headerBytes):], payloadBytes)
	return message
}
