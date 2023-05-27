package socks

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Client is a Socks5 client.
type Client struct {
	serverPicker  protocol.ServerPicker
	policyManager policy.Manager
	version       Version
	dns           dns.Client
}

// NewClient create a new Socks5 client based on the given config.
func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	serverList := protocol.NewServerList()
	for _, rec := range config.Server {
		s, err := protocol.NewServerSpecFromPB(rec)
		if err != nil {
			return nil, newError("failed to get server spec").Base(err)
		}
		serverList.AddServer(s)
	}
	if serverList.Size() == 0 {
		return nil, newError("0 target server")
	}

	v := core.MustFromContext(ctx)
	c := &Client{
		serverPicker:  protocol.NewRoundRobinServerPicker(serverList),
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		version:       config.Version,
	}
	if config.Version == Version_SOCKS4 {
		c.dns = v.GetFeature(dns.ClientType()).(dns.Client)
	}

	return c, nil
}

// Process implements proxy.Outbound.Process.
func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return newError("target not specified.")
	}
	outbound.Name = "socks"
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		inbound.SetCanSpliceCopy(2)
	}
	// Destination of the inner request.
	destination := outbound.Target

	// Outbound server.
	var server *protocol.ServerSpec
	// Outbound server's destination.
	var dest net.Destination
	// Connection to the outbound server.
	var conn stat.Connection

	if err := retry.ExponentialBackoff(5, 100).On(func() error {
		server = c.serverPicker.PickServer()
		dest = server.Destination()
		rawConn, err := dialer.Dial(ctx, dest)
		if err != nil {
			return err
		}
		conn = rawConn

		return nil
	}); err != nil {
		return newError("failed to find an available destination").Base(err)
	}

	defer func() {
		if err := conn.Close(); err != nil {
			newError("failed to closed connection").Base(err).WriteToLog(session.ExportIDToError(ctx))
		}
	}()

	p := c.policyManager.ForLevel(0)

	request := &protocol.RequestHeader{
		Version: socks5Version,
		Command: protocol.RequestCommandTCP,
		Address: destination.Address,
		Port:    destination.Port,
	}

	switch c.version {
	case Version_SOCKS4:
		if request.Address.Family().IsDomain() {
			ips, err := c.dns.LookupIP(request.Address.Domain(), dns.IPOption{
				IPv4Enable: true,
			})
			if err != nil {
				return err
			} else if len(ips) == 0 {
				return dns.ErrEmptyResponse
			}
			request.Address = net.IPAddress(ips[0])
		}
		fallthrough
	case Version_SOCKS4A:
		request.Version = socks4Version

		if destination.Network == net.Network_UDP {
			return newError("udp is not supported in socks4")
		} else if destination.Address.Family().IsIPv6() {
			return newError("ipv6 is not supported in socks4")
		}
	}

	if destination.Network == net.Network_UDP {
		request.Command = protocol.RequestCommandUDP
	}

	user := server.PickUser()
	if user != nil {
		request.User = user
		p = c.policyManager.ForLevel(user.Level)
	}

	if err := conn.SetDeadline(time.Now().Add(p.Timeouts.Handshake)); err != nil {
		newError("failed to set deadline for handshake").Base(err).WriteToLog(session.ExportIDToError(ctx))
	}
	udpRequest, err := ClientHandshake(request, conn, conn)
	if err != nil {
		return newError("failed to establish connection to server").AtWarning().Base(err)
	}
	if udpRequest != nil {
		if udpRequest.Address == net.AnyIP || udpRequest.Address == net.AnyIPv6 {
			udpRequest.Address = dest.Address
		}
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		newError("failed to clear deadline after handshake").Base(err).WriteToLog(session.ExportIDToError(ctx))
	}

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, p.Timeouts.ConnectionIdle)

	var requestFunc func() error
	var responseFunc func() error
	if request.Command == protocol.RequestCommandTCP {
		requestFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
			return buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer))
		}
		responseFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.UplinkOnly)
			return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
		}
	} else if request.Command == protocol.RequestCommandUDP {
		udpConn, err := dialer.Dial(ctx, udpRequest.Destination())
		if err != nil {
			return newError("failed to create UDP connection").Base(err)
		}
		defer udpConn.Close()
		requestFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
			writer := &UDPWriter{Writer: udpConn, Request: request}
			return buf.Copy(link.Reader, writer, buf.UpdateActivity(timer))
		}
		responseFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.UplinkOnly)
			reader := &UDPReader{Reader: udpConn}
			return buf.Copy(reader, link.Writer, buf.UpdateActivity(timer))
		}
	}

	if newCtx != nil {
		ctx = newCtx
	}

	responseDonePost := task.OnSuccess(responseFunc, task.Close(link.Writer))
	if err := task.Run(ctx, requestFunc, responseDonePost); err != nil {
		return newError("connection ends").Base(err)
	}

	return nil
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}
