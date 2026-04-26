package tun

import (
	stdnet "net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	tunicmp "github.com/xtls/xray-core/proxy/tun/icmp"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const defaultICMPEchoTimeout = 30 * time.Second

const (
	icmpEchoWorkerCount = 8
	icmpEchoQueueSize   = 256
	icmpDropLogEvery    = 64
)

type icmpEchoTask struct {
	netProto tcpip.NetworkProtocolNumber
	srcIP    tcpip.Address
	dstIP    tcpip.Address
	ident    uint16
	sequence uint16
	message  []byte
}

type icmpEchoDispatcher struct {
	stack     *stackGVisor
	ipv4Tasks chan icmpEchoTask
	ipv6Tasks chan icmpEchoTask
	done      chan struct{}
	onceStart sync.Once
	onceClose sync.Once
	dropped   atomic.Uint64
}

func newICMPEchoDispatcher(stack *stackGVisor) *icmpEchoDispatcher {
	return &icmpEchoDispatcher{
		stack:     stack,
		ipv4Tasks: make(chan icmpEchoTask, icmpEchoQueueSize),
		ipv6Tasks: make(chan icmpEchoTask, icmpEchoQueueSize),
		done:      make(chan struct{}),
	}
}

func (d *icmpEchoDispatcher) start() {
	d.onceStart.Do(func() {
		for i := 0; i < icmpEchoWorkerCount; i++ {
			go d.worker(header.IPv4ProtocolNumber, d.ipv4Tasks)
			go d.worker(header.IPv6ProtocolNumber, d.ipv6Tasks)
		}
	})
}

func (d *icmpEchoDispatcher) close() {
	d.onceClose.Do(func() {
		close(d.done)
	})
}

func (d *icmpEchoDispatcher) enqueue(task icmpEchoTask) bool {
	var queue chan icmpEchoTask
	switch task.netProto {
	case header.IPv4ProtocolNumber:
		queue = d.ipv4Tasks
	case header.IPv6ProtocolNumber:
		queue = d.ipv6Tasks
	default:
		return false
	}

	select {
	case queue <- task:
		return true
	default:
		dropped := d.dropped.Add(1)
		if dropped == 1 || dropped%icmpDropLogEvery == 0 {
			errors.LogDebug(d.stack.ctx, "[tun][icmp] dropping echo request because worker queue is full proto=", tunicmp.ProtocolLabel(task.netProto), " dropped=", dropped)
		}
		return false
	}
}

func (d *icmpEchoDispatcher) worker(netProto tcpip.NetworkProtocolNumber, tasks <-chan icmpEchoTask) {
	var socket *tunicmp.Socket
	replyBuf := make([]byte, 64<<10)

	for {
		select {
		case <-d.done:
			if socket != nil {
				_ = socket.Conn.Close()
			}
			return
		case task := <-tasks:
			if socket == nil {
				var err error
				socket, err = tunicmp.OpenEchoSocket(netProto, task.dstIP)
				if err != nil {
					errors.LogInfoInner(d.stack.ctx, err, "[tun] failed to proxy icmp echo")
					continue
				}
			}

			resetSocket, err := d.stack.forwardICMPEcho(task, socket, replyBuf)
			if err != nil {
				errors.LogInfoInner(d.stack.ctx, err, "[tun] failed to proxy icmp echo")
			}
			if resetSocket && socket != nil {
				_ = socket.Conn.Close()
				socket = nil
			}
		}
	}
}

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

	errors.LogDebug(t.ctx, "[tun][icmp] ", tunicmp.ProtocolLabel(netProto), " echo request ", srcIP, " -> ", dstIP, " id=", ident, " seq=", sequence)
	_ = t.icmpEcho.enqueue(icmpEchoTask{
		netProto: netProto,
		srcIP:    srcIP,
		dstIP:    dstIP,
		ident:    ident,
		sequence: sequence,
		message:  message,
	})

	return true
}

func (t *stackGVisor) forwardICMPEcho(task icmpEchoTask, socket *tunicmp.Socket, replyBuf []byte) (bool, error) {
	timeout := t.icmpEchoTimeout()
	if err := socket.Conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return true, errors.New("set icmp socket deadline").Base(err)
	}

	socketIdent, hasSocketIdent := socket.ReplyIdentifier()
	remoteAddr, err := socket.RemoteAddrFor(task.dstIP)
	if err != nil {
		return false, errors.New("resolve icmp remote address").Base(err)
	}
	request, err := tunicmp.MarshalEchoMessage(task.netProto, true, task.ident, task.sequence, tunicmp.Payload(task.message))
	if err != nil {
		return false, errors.New("marshal icmp echo request").Base(err)
	}

	if _, err := socket.Conn.WriteTo(request, remoteAddr); err != nil {
		return true, errors.New("send icmp echo request to ", remoteAddr).Base(err)
	}

	var packetsRead int
	for {
		n, addr, err := socket.Conn.ReadFrom(replyBuf)
		if err != nil {
			return !isICMPEchoTimeoutError(err), errors.New("read icmp echo reply after ", packetsRead, " packets").Base(err)
		}
		packetsRead++
		if !tunicmp.ReplyAddrMatches(addr, remoteAddr) {
			continue
		}

		reply := append([]byte(nil), replyBuf[:n]...)
		reply, err = tunicmp.NormalizeEchoReply(task.netProto, reply)
		if err != nil {
			return false, errors.New("normalize icmp echo reply from ", addr).Base(err)
		}
		replyIdent, ok := tunicmp.MatchEchoReply(task.netProto, reply, task.ident, task.sequence, socketIdent, hasSocketIdent)
		if !ok {
			continue
		}
		shouldSkipTunReply, err := socket.ShouldSkipSyntheticReply(stdnet.IP(task.srcIP.AsSlice()))
		if err != nil {
			errors.LogDebugInner(t.ctx, err, "[tun][icmp] failed to decide whether to skip synthetic echo reply")
		} else if shouldSkipTunReply {
			errors.LogDebug(t.ctx, "[tun][icmp] ", tunicmp.ProtocolLabel(task.netProto), " echo reply handled by local stack, skipping tun injection id=", task.ident, " seq=", task.sequence, " socket=", socket.Network)
			return false, nil
		}
		if replyIdent != task.ident {
			if err := tunicmp.RewriteEchoIdentifier(task.netProto, reply, task.ident); err != nil {
				return false, errors.New("rewrite icmp echo reply identifier").Base(err)
			}
		}
		if err := tunicmp.RewriteChecksum(task.netProto, reply, task.dstIP, task.srcIP); err != nil {
			return false, errors.New("rewrite icmp echo reply checksum").Base(err)
		}
		errors.LogDebug(t.ctx, "[tun][icmp] ", tunicmp.ProtocolLabel(task.netProto), " echo reply ", task.dstIP, " -> ", task.srcIP, " id=", task.ident, " seq=", task.sequence, " packetsRead=", packetsRead, " socket=", socket.Network)
		return false, t.writeRawICMPPacket(task.netProto, reply, task.dstIP, task.srcIP)
	}
}

func isICMPEchoTimeoutError(err error) bool {
	if netErr, ok := err.(stdnet.Error); ok {
		return netErr.Timeout()
	}
	return false
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
