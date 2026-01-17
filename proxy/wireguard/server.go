package wireguard

import (
	"context"
	goerrors "errors"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

var nullDestination = net.TCPDestination(net.AnyIP, 0)

type Server struct {
	bindServer *netBindServer

	info          routingInfo
	policyManager policy.Manager
}

type routingInfo struct {
	ctx         context.Context
	dispatcher  routing.Dispatcher
	inboundTag  *session.Inbound
	contentTag  *session.Content
}

func NewServer(ctx context.Context, conf *DeviceConfig) (*Server, error) {
	v := core.MustFromContext(ctx)

	endpoints, hasIPv4, hasIPv6, err := parseEndpoints(conf)
	if err != nil {
		return nil, err
	}

	server := &Server{
		bindServer: &netBindServer{
			netBind: netBind{
				dns: v.GetFeature(dns.ClientType()).(dns.Client),
				dnsOption: dns.IPOption{
					IPv4Enable: hasIPv4,
					IPv6Enable: hasIPv6,
				},
			},
		},
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}

	tun, err := conf.createTun()(endpoints, int(conf.Mtu), server.forwardConnection)
	if err != nil {
		return nil, err
	}

	if err = tun.BuildDevice(createIPCRequest(conf), server.bindServer); err != nil {
		_ = tun.Close()
		return nil, err
	}

	return server, nil
}

// Network implements proxy.Inbound.
func (*Server) Network() []net.Network {
	return []net.Network{net.Network_UDP}
}

// Process implements proxy.Inbound.
func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	s.info = routingInfo{
		ctx:        ctx,
		dispatcher: dispatcher,
		inboundTag: session.InboundFromContext(ctx),
		contentTag: session.ContentFromContext(ctx),
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
			if err != nil && goerrors.Is(err, io.EOF) {
				nep.conn = nil
				return nil
			}
		}
	}
}

func (s *Server) forwardConnection(dest net.Destination, conn net.Conn) {
	if s.info.dispatcher == nil {
		errors.LogError(s.info.ctx, "unexpected: dispatcher == nil")
		return
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(core.ToBackgroundDetachedContext(s.info.ctx))
	sid := session.NewID()
	ctx = c.ContextWithID(ctx, sid)
	inbound := session.Inbound{} // since promiscuousModeHandler mixed-up context, we shallow copy inbound (tag) and content (configs)
	if s.info.inboundTag != nil {
		inbound = *s.info.inboundTag
	}
	inbound.Name = "wireguard"
	inbound.CanSpliceCopy = 3

	// overwrite the source to use the tun address for each sub context.
	// Since gvisor.ForwarderRequest doesn't provide any info to associate the sub-context with the Parent context
	// Currently we have no way to link to the original source address
	inbound.Source = net.DestinationFromAddr(conn.RemoteAddr())
	ctx = session.ContextWithInbound(ctx, &inbound)
	if s.info.contentTag != nil {
		ctx = session.ContextWithContent(ctx, s.info.contentTag)
	}
	ctx = session.SubContextFromMuxInbound(ctx)

	plcy := s.policyManager.ForLevel(0)
	timer := signal.CancelAfterInactivity(ctx, cancel, plcy.Timeouts.ConnectionIdle)

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   nullDestination,
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
	})

	link, err := s.info.dispatcher.Dispatch(ctx, dest)
	if err != nil {
		errors.LogErrorInner(ctx, err, "dispatch connection")
	}
	defer cancel()

	requestDone := func() error {
		defer timer.SetTimeout(plcy.Timeouts.DownlinkOnly)
		if err := buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to transport all TCP request").Base(err)
		}

		return nil
	}

	responseDone := func() error {
		defer timer.SetTimeout(plcy.Timeouts.UplinkOnly)
		if err := buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to transport all TCP response").Base(err)
		}

		return nil
	}

	requestDonePost := task.OnSuccess(requestDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDonePost, responseDone); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		errors.LogDebugInner(ctx, err, "connection ends")
		return
	}
}
