package tun

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	defaultNIC tcpip.NICID = 1

	tcpRXBufMinSize = tcp.MinBufferSize
	tcpRXBufDefSize = tcp.DefaultSendBufferSize
	tcpRXBufMaxSize = 8 << 20 // 8MiB

	tcpTXBufMinSize = tcp.MinBufferSize
	tcpTXBufDefSize = tcp.DefaultReceiveBufferSize
	tcpTXBufMaxSize = 6 << 20 // 6MiB
)

// stackGVisor is ip stack implemented by gVisor package
type stackGVisor struct {
	ctx         context.Context
	tun         GVisorTun
	idleTimeout time.Duration
	handler     *Handler
	stack       *stack.Stack
	endpoint    stack.LinkEndpoint
}

// GVisorTun implements a bridge to connect gVisor ip stack to tun interface
type GVisorTun interface {
	newEndpoint() (stack.LinkEndpoint, error)
}

// NewStack builds new ip stack (using gVisor)
func NewStack(ctx context.Context, options StackOptions, handler *Handler) (Stack, error) {
	gStack := &stackGVisor{
		ctx:         ctx,
		tun:         options.Tun.(GVisorTun),
		idleTimeout: options.IdleTimeout,
		handler:     handler,
	}

	return gStack, nil
}

// Start is called by Handler to bring stack to life
func (t *stackGVisor) Start() error {
	linkEndpoint, err := t.tun.newEndpoint()
	if err != nil {
		return err
	}

	ipStack, err := createStack(linkEndpoint)
	if err != nil {
		return err
	}

	tcpForwarder := tcp.NewForwarder(ipStack, 0, 65535, func(r *tcp.ForwarderRequest) {
		go func(r *tcp.ForwarderRequest) {
			var wq waiter.Queue
			var id = r.ID()

			// Perform a TCP three-way handshake.
			ep, err := r.CreateEndpoint(&wq)
			if err != nil {
				errors.LogError(t.ctx, err.String())
				r.Complete(true)
				return
			}

			options := ep.SocketOptions()
			options.SetKeepAlive(false)
			options.SetReuseAddress(true)
			options.SetReusePort(true)

			t.handler.HandleConnection(
				gonet.NewTCPConn(&wq, ep),
				// local address on the gVisor side is connection destination
				net.TCPDestination(net.IPAddress(id.LocalAddress.AsSlice()), net.Port(id.LocalPort)),
			)

			// close the socket
			ep.Close()
			// send connection complete upstream
			r.Complete(false)
		}(r)
	})
	ipStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	// Use custom UDP packet handler instead of forwarder for FullCone NAT
	ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		t.handler.HandleUDPPacket(id, pkt, ipStack)
		return true
	})

	t.stack = ipStack
	t.endpoint = linkEndpoint

	return nil
}

// Close is called by Handler to shut down the stack
func (t *stackGVisor) Close() error {
	if t.stack == nil {
		return nil
	}
	t.endpoint.Attach(nil)
	t.stack.Close()
	for _, endpoint := range t.stack.CleanupEndpoints() {
		endpoint.Abort()
	}

	return nil
}

// createStack configure gVisor ip stack
func createStack(ep stack.LinkEndpoint) (*stack.Stack, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        false,
	}
	gStack := stack.New(opts)

	err := gStack.CreateNIC(defaultNIC, ep)
	if err != nil {
		return nil, errors.New(err.String())
	}

	gStack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: defaultNIC},
		{Destination: header.IPv6EmptySubnet, NIC: defaultNIC},
	})

	err = gStack.SetSpoofing(defaultNIC, true)
	if err != nil {
		return nil, errors.New(err.String())
	}
	err = gStack.SetPromiscuousMode(defaultNIC, true)
	if err != nil {
		return nil, errors.New(err.String())
	}

	cOpt := tcpip.CongestionControlOption("cubic")
	gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &cOpt)
	sOpt := tcpip.TCPSACKEnabled(true)
	gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sOpt)
	mOpt := tcpip.TCPModerateReceiveBufferOption(true)
	gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &mOpt)

	tcpRXBufOpt := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     tcpRXBufMinSize,
		Default: tcpRXBufDefSize,
		Max:     tcpRXBufMaxSize,
	}
	err = gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpRXBufOpt)
	if err != nil {
		return nil, errors.New(err.String())
	}

	tcpTXBufOpt := tcpip.TCPSendBufferSizeRangeOption{
		Min:     tcpTXBufMinSize,
		Default: tcpTXBufDefSize,
		Max:     tcpTXBufMaxSize,
	}
	err = gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpTXBufOpt)
	if err != nil {
		return nil, errors.New(err.String())
	}

	return gStack, nil
}

// HandleUDPPacket handles incoming UDP packets for FullCone NAT
func (t *Handler) HandleUDPPacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer, ipStack *stack.Stack) {
src := net.UDPDestination(net.IPAddress(id.RemoteAddress.AsSlice()), net.Port(id.RemotePort))
dest := net.UDPDestination(net.IPAddress(id.LocalAddress.AsSlice()), net.Port(id.LocalPort))
data := pkt.Data().AsRange().ToSlice()
if len(data) == 0 {
return
}

t.Lock()
conn, found := t.udpConns[src]
if !found {
reader, writer := pipe.New(pipe.DiscardOverflow(), pipe.WithSizeLimit(16*1024))
conn = &udpConn{reader: reader, writer: writer, done: done.New()}
t.udpConns[src] = conn
if t.udpChecker != nil && len(t.udpConns) == 1 {
common.Must(t.udpChecker.Start())
}
t.Unlock()

go func() {
ctx, cancel := context.WithCancel(t.ctx)
conn.cancel = cancel
defer func() {
cancel()
t.Lock()
delete(t.udpConns, src)
t.Unlock()
common.Must(conn.done.Close())
common.Must(common.Close(conn.writer))
}()

inbound := &session.Inbound{
Name:          "tun",
Source:        src,
CanSpliceCopy: 1,
User:          &protocol.MemoryUser{Level: t.config.UserLevel},
}
ctx = session.ContextWithInbound(c.ContextWithID(ctx, session.NewID()), inbound)
ctx = session.SubContextFromMuxInbound(ctx)
link := &transport.Link{
Reader: &buf.TimeoutWrapperReader{Reader: conn.reader},
Writer: &udpWriter{stack: ipStack, src: dest, dest: src},
}
t.dispatcher.DispatchLink(ctx, dest, link)
}()
} else {
conn.lastActive.Store(time.Now().Unix())
t.Unlock()
}

b := buf.New()
b.Write(data)
b.UDP = &dest
conn.writer.WriteMultiBuffer(buf.MultiBuffer{b})
}

type udpWriter struct {
stack *stack.Stack
src   net.Destination
dest  net.Destination
}

func (w *udpWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
for _, b := range mb {
// Use b.UDP as source if available, otherwise use w.dest
srcAddr := w.dest
if b.UDP != nil {
srcAddr = *b.UDP
}

// Validate address family matches
if srcAddr.Address.Family() != w.src.Address.Family() {
errors.LogWarning(context.Background(), "UDP return packet address family mismatch: expected ", w.src.Address.Family(), ", got ", srcAddr.Address.Family())
b.Release()
continue
}

payload := b.Bytes()
udpLen := header.UDPMinimumSize + len(payload)
srcIP := tcpip.AddrFromSlice(srcAddr.Address.IP())
dstIP := tcpip.AddrFromSlice(w.src.Address.IP())

// Build packet with appropriate IP header size
isIPv4 := w.src.Address.Family().IsIPv4()
ipHdrSize := header.IPv6MinimumSize
netProto := header.IPv6ProtocolNumber
if isIPv4 {
ipHdrSize = header.IPv4MinimumSize
netProto = header.IPv4ProtocolNumber
}

pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
ReserveHeaderBytes: ipHdrSize + header.UDPMinimumSize,
Payload:            buffer.MakeWithData(payload),
})

// Build UDP header
udpHdr := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
udpHdr.Encode(&header.UDPFields{
SrcPort: uint16(srcAddr.Port),
DstPort: uint16(w.src.Port),
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
w.stack.WriteRawPacket(defaultNIC, netProto, buffer.MakeWithData(data))
pkt.DecRef()
b.Release()
}
return nil
}
