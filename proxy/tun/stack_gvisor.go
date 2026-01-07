package tun

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
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

	udpForwarder := udp.NewForwarder(ipStack, func(r *udp.ForwarderRequest) {
		go func(r *udp.ForwarderRequest) {
			var wq waiter.Queue
			var id = r.ID()

			ep, err := r.CreateEndpoint(&wq)
			if err != nil {
				errors.LogError(t.ctx, err.String())
				return
			}

			options := ep.SocketOptions()
			options.SetReuseAddress(true)
			options.SetReusePort(true)

			t.handler.HandleConnection(
				gonet.NewUDPConn(&wq, ep),
				// local address on the gVisor side is connection destination
				net.UDPDestination(net.IPAddress(id.LocalAddress.AsSlice()), net.Port(id.LocalPort)),
			)

			// close the socket
			ep.Close()
		}(r)
	})
	ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

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
