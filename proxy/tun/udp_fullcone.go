package tun

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// udp connection abstraction
type udpConn struct {
	lastActive atomic.Int64
	reader     buf.Reader
	writer     buf.Writer
	done       *done.Instance
	cancel     context.CancelFunc
}

// sub-handler specifically for udp connections under main handler
type udpConnectionHandler struct {
	sync.Mutex
	ctx         context.Context
	handler     *Handler
	udpConns    map[net.Destination]*udpConn
	udpChecker  *task.Periodic
	writePacket func(p []byte)
}

func newUdpConnectionHandler(ctx context.Context, h *Handler, writePacket func(p []byte)) *udpConnectionHandler {
	handler := &udpConnectionHandler{
		ctx:         ctx,
		handler:     h,
		udpConns:    make(map[net.Destination]*udpConn),
		writePacket: writePacket,
	}

	handler.udpChecker = &task.Periodic{Interval: time.Minute, Execute: handler.cleanupUDP}
	handler.udpChecker.Start()

	return handler
}

func (u *udpConnectionHandler) cleanupUDP() error {
	u.Lock()
	defer u.Unlock()
	if len(u.udpConns) == 0 {
		return errors.New("no connections")
	}
	now := time.Now().Unix()
	for src, conn := range u.udpConns {
		if now-conn.lastActive.Load() > 300 {
			conn.cancel()
			common.Must(conn.done.Close())
			common.Must(common.Close(conn.writer))
			delete(u.udpConns, src)
		}
	}
	return nil
}

// HandlePacket handles UDP packets coming from tun, to forward to the dispatcher
// this custom handler support FullCone NAT of returning packets, binding connection only by the source port
func (u *udpConnectionHandler) HandlePacket(src net.Destination, dst net.Destination, data []byte) bool {
	u.Lock()
	conn, found := u.udpConns[src]
	if !found {
		reader, writer := pipe.New(pipe.DiscardOverflow(), pipe.WithSizeLimit(16*1024))
		conn = &udpConn{reader: reader, writer: writer, done: done.New()}
		u.udpConns[src] = conn
		u.Unlock()

		go func() {
			ctx, cancel := context.WithCancel(u.ctx)
			conn.cancel = cancel
			defer func() {
				cancel()
				u.Lock()
				delete(u.udpConns, src)
				u.Unlock()
				common.Must(conn.done.Close())
				common.Must(common.Close(conn.writer))
			}()

			inbound := &session.Inbound{
				Name:          "tun",
				Source:        src,
				CanSpliceCopy: 1,
				User:          &protocol.MemoryUser{Level: u.handler.config.UserLevel},
			}
			ctx = session.ContextWithInbound(c.ContextWithID(ctx, session.NewID()), inbound)
			ctx = session.SubContextFromMuxInbound(ctx)
			link := &transport.Link{
				Reader: &buf.TimeoutWrapperReader{Reader: conn.reader},
				// reverse source and destination, indicating the packets to write are going in the other
				// direction (written back to tun) and should have reversed addressing
				Writer: &udpWriter{handler: u, src: dst, dst: src},
			}
			_ = u.handler.dispatcher.DispatchLink(ctx, dst, link)
		}()
	} else {
		conn.lastActive.Store(time.Now().Unix())
		u.Unlock()
	}

	b := buf.New()
	b.Write(data)
	b.UDP = &dst
	conn.writer.WriteMultiBuffer(buf.MultiBuffer{b})

	return true
}

type udpWriter struct {
	handler *udpConnectionHandler
	// address in the side of stack, where packet will be coming from
	src net.Destination
	// address on the side of tun, where packet will be destined to
	dst net.Destination
}

func (w *udpWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for _, b := range mb {
		// use captured in the dispatched packet source address b.UDP as source, if available,
		// otherwise use captured in the writer source w.src
		srcAddr := w.src
		if b.UDP != nil {
			srcAddr = *b.UDP
		}

		// validate address family matches
		if srcAddr.Address.Family() != w.src.Address.Family() {
			errors.LogWarning(context.Background(), "UDP return packet address family mismatch: expected ", w.src.Address.Family(), ", got ", srcAddr.Address.Family())
			b.Release()
			continue
		}

		payload := b.Bytes()
		udpLen := header.UDPMinimumSize + len(payload)
		srcIP := tcpip.AddrFromSlice(srcAddr.Address.IP())
		dstIP := tcpip.AddrFromSlice(w.dst.Address.IP())

		// build packet with appropriate IP header size
		isIPv4 := srcAddr.Address.Family().IsIPv4()
		ipHdrSize := header.IPv6MinimumSize
		if isIPv4 {
			ipHdrSize = header.IPv4MinimumSize
		}

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: ipHdrSize + header.UDPMinimumSize,
			Payload:            buffer.MakeWithData(payload),
		})

		// Build UDP header
		udpHdr := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
		udpHdr.Encode(&header.UDPFields{
			SrcPort: uint16(srcAddr.Port),
			DstPort: uint16(w.dst.Port),
			Length:  uint16(udpLen),
		})

		// Calculate and set UDP checksum
		xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, srcIP, dstIP, uint16(udpLen))
		udpHdr.SetChecksum(^udpHdr.CalculateChecksum(checksum.Checksum(payload, xsum)))

		// Build IP header
		if isIPv4 {
			ipHdr := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
			ipHdr.Encode(&header.IPv4Fields{
				TotalLength: uint16(header.IPv4MinimumSize + udpLen),
				TTL:         64,
				Protocol:    uint8(header.UDPProtocolNumber),
				SrcAddr:     srcIP,
				DstAddr:     dstIP,
			})
			ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
		} else {
			ipHdr := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
			ipHdr.Encode(&header.IPv6Fields{
				PayloadLength:     uint16(udpLen),
				TransportProtocol: header.UDPProtocolNumber,
				HopLimit:          64,
				SrcAddr:           srcIP,
				DstAddr:           dstIP,
			})
		}

		// Write raw packet to network stack
		views := pkt.AsSlices()
		var data []byte
		for _, view := range views {
			data = append(data, view...)
		}
		w.handler.writePacket(data)
		pkt.DecRef()
		b.Release()
	}
	return nil
}
