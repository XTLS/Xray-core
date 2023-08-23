package wireguard

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/sagernet/wireguard-go/device"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var nullDestination = net.TCPDestination(net.AnyIP, 0)

type Server struct {
	device     *device.Device
	bindServer *netBindServer

	info routingInfo
}

type routingInfo struct {
	ctx         context.Context
	dispatcher  routing.Dispatcher
	inboundTag  *session.Inbound
	outboundTag *session.Outbound
	contentTag  *session.Content
}

func NewServer(ctx context.Context, config *DeviceConfig) (*Server, error) {
	v := core.MustFromContext(ctx)

	endpoints, err := parseEndpoints(config)
	if err != nil {
		return nil, err
	}

	tun, tnet, err := CreateNetTUN(endpoints, int(config.Mtu), false)
	if err != nil {
		return nil, err
	}

	server := &Server{
		bindServer: &netBindServer{
			netBind: netBind{
				dns: v.GetFeature(dns.ClientType()).(dns.Client),
				dnsOption: dns.IPOption{
					IPv4Enable: tnet.HasV4(),
					IPv6Enable: tnet.HasV6(),
				},
			},
		},
	}

	server.setConnectionHandler(tnet.stack)

	dev := device.NewDevice(tun, server.bindServer, wgLogger, int(config.NumWorkers))
	err = dev.IpcSet(createIPCRequest(config))
	if err != nil {
		return nil, err
	}
	err = dev.Up()
	if err != nil {
		return nil, err
	}

	server.device = dev

	return server, nil
}

// Network implements proxy.Inbound.
func (*Server) Network() []net.Network {
	return []net.Network{net.Network_UDP}
}

// Process implements proxy.Inbound.
func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	s.info = routingInfo{
		ctx:         core.ToBackgroundDetachedContext(ctx),
		dispatcher:  dispatcher,
		inboundTag:  session.InboundFromContext(ctx),
		outboundTag: session.OutboundFromContext(ctx),
		contentTag:  session.ContentFromContext(ctx),
	}

	ep, err := s.bindServer.ParseEndpoint(conn.RemoteAddr().String())
	if err != nil {
		return err
	}

	nep := ep.(*netEndpoint)
	nep.conn = conn

	reader := buf.NewPacketReader(conn)
	for {
		mpayload, err := reader.ReadMultiBuffer()
		if err != nil {
			return err
		}

		for _, payload := range mpayload {
			v, ok := <-s.bindServer.readQueue
			if !ok {
				return nil
			}
			i, err := payload.Read(v.buff)

			v.bytes = i
			v.endpoint = nep
			v.err = err
			v.waiter.Done()
			if err != nil && errors.Is(err, io.EOF) {
				nep.conn = nil
				return nil
			}
		}
	}
}

func (s *Server) setConnectionHandler(stack *stack.Stack) {
	tcpForwarder := tcp.NewForwarder(stack, 0, 2048, func(r *tcp.ForwarderRequest) {
		var (
			wq waiter.Queue
			id = r.ID()
		)

		// Perform a TCP three-way handshake.
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			newError(err.String()).AtError().WriteToLog()
			r.Complete(true)
			return
		}
		r.Complete(false)

		ep.SocketOptions().SetKeepAlive(true)

		// local address is actually destination
		go forwardConnection(s.info, net.TCPDestination(net.IPAddress([]byte(id.LocalAddress)), net.Port(id.LocalPort)), gonet.NewTCPConn(&wq, ep))
	})
	stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	udpForwarder := udp.NewForwarder(stack, func(r *udp.ForwarderRequest) {
		var (
			wq waiter.Queue
			id = r.ID()
		)

		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			newError(err.String()).AtError().WriteToLog()
			return
		}
		// prevents hanging connections and ensure timely release
		ep.SocketOptions().SetLinger(tcpip.LingerOption{
			Enabled: true,
			Timeout: 15 * time.Second,
		})

		go forwardConnection(s.info, net.UDPDestination(net.IPAddress([]byte(id.LocalAddress)), net.Port(id.LocalPort)), gonet.NewUDPConn(stack, &wq, ep))
	})
	stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
}

func forwardConnection(info routingInfo, dest net.Destination, conn net.Conn) {
	if info.dispatcher == nil {
		newError("unexpected: dispatcher == nil").AtError().WriteToLog()
		return
	}

	ctx, cancel := context.WithCancel(core.ToBackgroundDetachedContext(info.ctx))
	defer cancel()

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   nullDestination,
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
	})

	if info.inboundTag != nil {
		ctx = session.ContextWithInbound(ctx, info.inboundTag)
	}
	if info.outboundTag != nil {
		ctx = session.ContextWithOutbound(ctx, info.outboundTag)
	}
	if info.contentTag != nil {
		ctx = session.ContextWithContent(ctx, info.contentTag)
	}

	link, err := info.dispatcher.Dispatch(ctx, dest)
	if err != nil {
		newError("dispatch connection").Base(err).AtError().WriteToLog()
	}
	defer cancel()

	requestDone := func() error {
		if err := buf.Copy(buf.NewReader(conn), link.Writer); err != nil {
			return newError("failed to transport all TCP request").Base(err)
		}

		return nil
	}

	responseDone := func() error {
		if err := buf.Copy(link.Reader, buf.NewWriter(conn)); err != nil {
			return newError("failed to transport all TCP response").Base(err)
		}

		return nil
	}

	requestDonePost := task.OnSuccess(requestDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDonePost, responseDone); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		newError("connection ends").Base(err).AtDebug().WriteToLog()
		return
	}
}
