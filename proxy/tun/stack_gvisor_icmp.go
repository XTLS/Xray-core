package tun

import (
	stdnet "net"
	"os"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
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
	ident, sequence, ok := parseICMPEchoRequest(netProto, message)
	if !ok {
		return true
	}

	errors.LogInfo(t.ctx, "[tun][icmp] ", icmpProtocolLabel(netProto), " echo request ", srcIP, " -> ", dstIP, " id=", ident, " seq=", sequence)

	go func() {
		if err := t.forwardICMPEcho(netProto, srcIP, dstIP, ident, sequence, message); err != nil {
			errors.LogInfoInner(t.ctx, err, "[tun] failed to proxy icmp echo")
		}
	}()

	return true
}

func (t *stackGVisor) forwardICMPEcho(netProto tcpip.NetworkProtocolNumber, srcIP, dstIP tcpip.Address, ident, sequence uint16, message []byte) error {
	timeout := t.icmpEchoTimeout()
	socketConfig, conn, err := openICMPEchoSocket(netProto, dstIP)
	if err != nil {
		return errors.New("listen icmp socket").Base(err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return errors.New("set icmp socket deadline").Base(err)
	}

	request, err := marshalICMPEchoMessage(netProto, true, ident, sequence, icmpPayload(message))
	if err != nil {
		return errors.New("marshal icmp echo request").Base(err)
	}

	if _, err := conn.WriteTo(request, socketConfig.remoteAddr); err != nil {
		return errors.New("send icmp echo request to ", socketConfig.remoteAddr).Base(err)
	}

	replyBuf := make([]byte, 64<<10)
	var packetsRead int
	for {
		n, addr, err := conn.ReadFrom(replyBuf)
		if err != nil {
			return errors.New("read icmp echo reply after ", packetsRead, " packets").Base(err)
		}
		packetsRead++
		if !icmpReplyAddrMatches(addr, socketConfig.remoteAddr) {
			continue
		}

		reply := append([]byte(nil), replyBuf[:n]...)
		reply, err = normalizeICMPEchoReply(netProto, reply)
		if err != nil {
			return errors.New("normalize icmp echo reply from ", addr).Base(err)
		}
		if !isMatchingICMPEchoReply(netProto, reply, ident, sequence) {
			continue
		}
		if isDatagramICMPNetwork(socketConfig.network) {
			isLocal, err := xnet.IsLocal(stdnet.IP(srcIP.AsSlice()))
			if err != nil {
				errors.LogInfoInner(t.ctx, err, "[tun][icmp] failed to determine whether source is local")
			} else if isLocal {
				errors.LogInfo(t.ctx, "[tun][icmp] ", icmpProtocolLabel(netProto), " echo reply handled by local stack, skipping tun injection id=", ident, " seq=", sequence, " socket=", socketConfig.network)
				return nil
			}
		}
		if err := rewriteICMPChecksum(netProto, reply, dstIP, srcIP); err != nil {
			return errors.New("rewrite icmp echo reply checksum").Base(err)
		}
		errors.LogInfo(t.ctx, "[tun][icmp] ", icmpProtocolLabel(netProto), " echo reply ", dstIP, " -> ", srcIP, " id=", ident, " seq=", sequence, " packetsRead=", packetsRead, " socket=", socketConfig.network)
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

func icmpPayload(message []byte) []byte {
	if len(message) < header.ICMPv4PayloadOffset {
		return nil
	}
	return append([]byte(nil), message[header.ICMPv4PayloadOffset:]...)
}

func parseICMPEchoRequest(netProto tcpip.NetworkProtocolNumber, message []byte) (uint16, uint16, bool) {
	switch netProto {
	case header.IPv4ProtocolNumber:
		if len(message) < header.ICMPv4MinimumSize {
			return 0, 0, false
		}
		icmpHdr := header.ICMPv4(message)
		if icmpHdr.Type() != header.ICMPv4Echo || icmpHdr.Code() != header.ICMPv4UnusedCode {
			return 0, 0, false
		}
		return icmpHdr.Ident(), icmpHdr.Sequence(), true
	case header.IPv6ProtocolNumber:
		if len(message) < header.ICMPv6MinimumSize {
			return 0, 0, false
		}
		icmpHdr := header.ICMPv6(message)
		if icmpHdr.Type() != header.ICMPv6EchoRequest || icmpHdr.Code() != header.ICMPv6UnusedCode {
			return 0, 0, false
		}
		return icmpHdr.Ident(), icmpHdr.Sequence(), true
	default:
		return 0, 0, false
	}
}

func isMatchingICMPEchoReply(netProto tcpip.NetworkProtocolNumber, message []byte, ident, sequence uint16) bool {
	switch netProto {
	case header.IPv4ProtocolNumber:
		if len(message) < header.ICMPv4MinimumSize {
			return false
		}
		icmpHdr := header.ICMPv4(message)
		return icmpHdr.Type() == header.ICMPv4EchoReply &&
			icmpHdr.Code() == header.ICMPv4UnusedCode &&
			icmpHdr.Ident() == ident &&
			icmpHdr.Sequence() == sequence
	case header.IPv6ProtocolNumber:
		if len(message) < header.ICMPv6MinimumSize {
			return false
		}
		icmpHdr := header.ICMPv6(message)
		return icmpHdr.Type() == header.ICMPv6EchoReply &&
			icmpHdr.Code() == header.ICMPv6UnusedCode &&
			icmpHdr.Ident() == ident &&
			icmpHdr.Sequence() == sequence
	default:
		return false
	}
}

func normalizeICMPEchoReply(netProto tcpip.NetworkProtocolNumber, message []byte) ([]byte, error) {
	switch netProto {
	case header.IPv4ProtocolNumber:
		if len(message) >= header.IPv4MinimumSize && message[0]>>4 == 4 {
			headerLen := int(message[0]&0x0f) * 4
			if headerLen < header.IPv4MinimumSize || headerLen > len(message) {
				return nil, errors.New("invalid ipv4 header in icmp reply")
			}
			return message[headerLen:], nil
		}
	case header.IPv6ProtocolNumber:
		if len(message) >= header.IPv6MinimumSize && message[0]>>4 == 6 {
			if len(message) < header.IPv6MinimumSize {
				return nil, errors.New("invalid ipv6 header in icmp reply")
			}
			return message[header.IPv6MinimumSize:], nil
		}
	}
	return message, nil
}

func marshalICMPEchoMessage(netProto tcpip.NetworkProtocolNumber, request bool, ident, sequence uint16, payload []byte) ([]byte, error) {
	msg := icmp.Message{
		Code: 0,
		Body: &icmp.Echo{
			ID:   int(ident),
			Seq:  int(sequence),
			Data: payload,
		},
	}

	switch netProto {
	case header.IPv4ProtocolNumber:
		if request {
			msg.Type = ipv4.ICMPTypeEcho
		} else {
			msg.Type = ipv4.ICMPTypeEchoReply
		}
	case header.IPv6ProtocolNumber:
		if request {
			msg.Type = ipv6.ICMPTypeEchoRequest
		} else {
			msg.Type = ipv6.ICMPTypeEchoReply
		}
	default:
		return nil, errors.New("unsupported icmp network protocol")
	}

	return msg.Marshal(nil)
}

func rewriteICMPChecksum(netProto tcpip.NetworkProtocolNumber, message []byte, srcIP, dstIP tcpip.Address) error {
	switch netProto {
	case header.IPv4ProtocolNumber:
		if len(message) < header.ICMPv4MinimumSize {
			return errors.New("invalid icmpv4 packet")
		}
		icmpHdr := header.ICMPv4(message)
		icmpHdr.SetChecksum(0)
		icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr[:header.ICMPv4MinimumSize], checksum.Checksum(icmpHdr.Payload(), 0)))
		return nil
	case header.IPv6ProtocolNumber:
		if len(message) < header.ICMPv6MinimumSize {
			return errors.New("invalid icmpv6 packet")
		}
		icmpHdr := header.ICMPv6(message)
		icmpHdr.SetChecksum(0)
		icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header:      icmpHdr[:header.ICMPv6MinimumSize],
			Src:         srcIP,
			Dst:         dstIP,
			PayloadCsum: checksum.Checksum(icmpHdr.Payload(), 0),
			PayloadLen:  len(icmpHdr.Payload()),
		}))
		return nil
	default:
		return errors.New("unsupported icmp network protocol")
	}
}

type icmpSocketConfig struct {
	network           string
	controllerNetwork string
	listenAddr        string
	remoteAddr        stdnet.Addr
}

func icmpSocketCandidates(netProto tcpip.NetworkProtocolNumber, dstIP tcpip.Address) []icmpSocketConfig {
	switch netProto {
	case header.IPv4ProtocolNumber:
		ip := stdnet.IP(dstIP.AsSlice())
		return []icmpSocketConfig{
			{network: "udp4", controllerNetwork: "udp4", listenAddr: "0.0.0.0", remoteAddr: &stdnet.UDPAddr{IP: ip}},
			{network: "ip4:icmp", controllerNetwork: "ip4", listenAddr: "0.0.0.0", remoteAddr: &stdnet.IPAddr{IP: ip}},
		}
	case header.IPv6ProtocolNumber:
		ip := stdnet.IP(dstIP.AsSlice())
		return []icmpSocketConfig{
			{network: "udp6", controllerNetwork: "udp6", listenAddr: "::", remoteAddr: &stdnet.UDPAddr{IP: ip}},
			{network: "ip6:ipv6-icmp", controllerNetwork: "ip6", listenAddr: "::", remoteAddr: &stdnet.IPAddr{IP: ip}},
		}
	default:
		return nil
	}
}

func openICMPEchoSocket(netProto tcpip.NetworkProtocolNumber, dstIP tcpip.Address) (icmpSocketConfig, stdnet.PacketConn, error) {
	var errs []interface{}
	for _, candidate := range icmpSocketCandidates(netProto, dstIP) {
		conn, err := listenICMPEcho(candidate)
		if err == nil {
			return candidate, conn, nil
		}
		errs = append(errs, candidate.network, ": ", err, "; ")
	}
	return icmpSocketConfig{}, nil, errors.New(errs...)
}

func listenICMPEcho(config icmpSocketConfig) (stdnet.PacketConn, error) {
	if isDatagramICMPNetwork(config.network) {
		return listenICMPDatagram(config)
	}

	conn, err := stdnet.ListenPacket(config.network, config.listenAddr)
	if err != nil {
		return nil, err
	}

	sysConn, ok := conn.(syscall.Conn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("icmp packet conn does not expose syscall conn")
	}

	rawConn, err := sysConn.SyscallConn()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := applyRawSocketControllers(config.controllerNetwork, config.remoteAddr.String(), rawConn); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}

func listenICMPDatagram(config icmpSocketConfig) (stdnet.PacketConn, error) {
	family := syscall.AF_INET
	proto := syscall.IPPROTO_ICMP
	var sa syscall.Sockaddr = &syscall.SockaddrInet4{}

	switch config.network {
	case "udp4":
	case "udp6":
		family = syscall.AF_INET6
		proto = syscall.IPPROTO_ICMPV6
		sa = &syscall.SockaddrInet6{}
	default:
		return nil, errors.New("unsupported datagram icmp network: ", config.network)
	}

	fd, err := syscall.Socket(family, syscall.SOCK_DGRAM, proto)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	if err := syscall.Bind(fd, sa); err != nil {
		_ = syscall.Close(fd)
		return nil, os.NewSyscallError("bind", err)
	}

	file := os.NewFile(uintptr(fd), "icmp datagram")
	conn, err := stdnet.FilePacketConn(file)
	_ = file.Close()
	if err != nil {
		return nil, err
	}

	sysConn, ok := conn.(syscall.Conn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("icmp datagram conn does not expose syscall conn")
	}

	rawConn, err := sysConn.SyscallConn()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := applyRawSocketControllers(config.controllerNetwork, config.remoteAddr.String(), rawConn); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}

func icmpProtocolLabel(netProto tcpip.NetworkProtocolNumber) string {
	switch netProto {
	case header.IPv4ProtocolNumber:
		return "ipv4"
	case header.IPv6ProtocolNumber:
		return "ipv6"
	default:
		return "unknown"
	}
}

func isDatagramICMPNetwork(network string) bool {
	return network == "udp4" || network == "udp6"
}

func icmpReplyAddrMatches(addr, expected stdnet.Addr) bool {
	switch expected := expected.(type) {
	case *stdnet.IPAddr:
		ipAddr, ok := addr.(*stdnet.IPAddr)
		return ok && ipAddr.IP.Equal(expected.IP)
	case *stdnet.UDPAddr:
		udpAddr, ok := addr.(*stdnet.UDPAddr)
		return ok && udpAddr.IP.Equal(expected.IP)
	default:
		return false
	}
}

func applyRawSocketControllers(network, address string, rawConn syscall.RawConn) error {
	internet.ControllersLock.Lock()
	controllers := append([]func(string, string, syscall.RawConn) error(nil), internet.Controllers...)
	internet.ControllersLock.Unlock()

	for _, ctl := range controllers {
		if err := ctl(network, address, rawConn); err != nil {
			return err
		}
	}

	return nil
}
