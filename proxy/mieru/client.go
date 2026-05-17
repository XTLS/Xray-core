package mieru

import (
	"context"
	stdnet "net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	mieruclient "github.com/enfein/mieru/v3/apis/client"
	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/mieru/account"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// Client is an outbound handler for the mieru protocol.
type Client struct {
	server        *protocol.ServerSpec
	mieru         mieruclient.Client
	transport     appctlpb.TransportProtocol
	policyManager policy.Manager

	streamDialer *xrayStreamDialer
	packetDialer *xrayPacketDialer

	startOnce sync.Once
	startErr  error
}

// NewClient creates a new mieru outbound client.
func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	if config.Server == nil {
		return nil, errors.New("no target server found")
	}
	server, err := protocol.NewServerSpecFromPB(config.Server)
	if err != nil {
		return nil, errors.New("failed to get server spec").Base(err)
	}
	if server.User == nil {
		return nil, errors.New("mieru outbound requires exactly one user")
	}
	acc, ok := server.User.Account.(*account.MemoryAccount)
	if !ok {
		return nil, errors.New("mieru outbound user is not a mieru account")
	}
	if acc.Username == "" || acc.Password == "" {
		return nil, errors.New("mieru outbound user is missing username/password")
	}

	tp, err := parseTransportProtocol(config.Transport)
	if err != nil {
		return nil, err
	}

	v := core.MustFromContext(ctx)
	c := &Client{
		server:        server,
		transport:     tp,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}

	dest := server.Destination
	port := int32(dest.Port)

	portBinding := &appctlpb.PortBinding{
		Port:     proto.Int32(port),
		Protocol: tp.Enum(),
	}

	ep := &appctlpb.ServerEndpoint{
		PortBindings: []*appctlpb.PortBinding{portBinding},
	}
	if dest.Address.Family().IsIP() {
		ep.IpAddress = proto.String(dest.Address.IP().String())
	} else {
		ep.DomainName = proto.String(dest.Address.Domain())
	}

	profile := &appctlpb.ClientProfile{
		ProfileName: proto.String("xray-mieru-out"),
		User: &appctlpb.User{
			Name:     proto.String(acc.Username),
			Password: proto.String(acc.Password),
		},
		Servers: []*appctlpb.ServerEndpoint{ep},
	}
	if config.Mtu > 0 {
		profile.Mtu = proto.Int32(config.Mtu)
	}
	if config.HandshakeMode != 0 {
		hm := appctlpb.HandshakeMode(config.HandshakeMode)
		profile.HandshakeMode = hm.Enum()
	}
	if level, ok := parseMultiplexingLevel(config.Multiplexing); ok {
		profile.Multiplexing = &appctlpb.MultiplexingConfig{
			Level: level.Enum(),
		}
	}

	c.streamDialer = &xrayStreamDialer{server: server.Destination}
	c.packetDialer = &xrayPacketDialer{server: server.Destination}

	mc := mieruclient.NewClient()
	if err := mc.Store(&mieruclient.ClientConfig{
		Profile: profile,
		// Skip mieru's internal DNS resolution: xray's dialer already resolves
		// destinations via the configured router/DNS pipeline.
		DNSConfig:    &apicommon.ClientDNSConfig{BypassDialerDNS: true},
		Dialer:       c.streamDialer,
		PacketDialer: c.packetDialer,
	}); err != nil {
		return nil, errors.New("failed to store mieru client config").Base(err)
	}
	c.mieru = mc

	return c, nil
}

// Process implements proxy.Outbound.
func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "mieru"
	ob.CanSpliceCopy = 3
	target := ob.Target

	if target.Network != net.Network_TCP && target.Network != net.Network_UDP {
		return errors.New("mieru only supports TCP/UDP targets, got ", target.Network)
	}

	// The xray dialer is per-request. We publish it into the shared atomic
	// pointer that our dialer adapters consult on every connect attempt.
	if c.transport == appctlpb.TransportProtocol_TCP {
		c.streamDialer.set(dialer)
	} else {
		c.packetDialer.set(dialer)
	}

	if err := c.ensureStarted(); err != nil {
		return err
	}

	netAddr := toMieruAddr(target)
	proxyConn, err := c.mieru.DialContext(ctx, netAddr)
	if err != nil {
		return errors.New("mieru DialContext failed").Base(err)
	}
	defer proxyConn.Close()

	errors.LogInfo(ctx, "tunneling request via mieru to ", target, " through ", c.server.Destination.NetAddr())

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	sessionPolicy := c.policyManager.ForLevel(0)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, sessionPolicy.Timeouts.ConnectionIdle)
	if newCtx != nil {
		ctx = newCtx
	}

	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		return buf.Copy(link.Reader, buf.NewWriter(proxyConn), buf.UpdateActivity(timer))
	}
	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(buf.NewReader(proxyConn), link.Writer, buf.UpdateActivity(timer))
	}

	responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
		return errors.New("connection ends").Base(err)
	}
	return nil
}

// ensureStarted starts the underlying mieru client exactly once.
func (c *Client) ensureStarted() error {
	c.startOnce.Do(func() {
		if err := c.mieru.Start(); err != nil {
			c.startErr = errors.New("failed to start mieru client").Base(err)
		}
	})
	return c.startErr
}

// xrayStreamDialer adapts xray's internet.Dialer to mieru's stream Dialer.
// The underlying xray dialer is published per request via set().
type xrayStreamDialer struct {
	dialerHolder atomic.Pointer[internet.Dialer]
	server       net.Destination
}

func (d *xrayStreamDialer) set(id internet.Dialer) {
	d.dialerHolder.Store(&id)
}

func (d *xrayStreamDialer) get() internet.Dialer {
	p := d.dialerHolder.Load()
	if p == nil {
		return nil
	}
	return *p
}

var _ apicommon.Dialer = (*xrayStreamDialer)(nil)

func (d *xrayStreamDialer) DialContext(ctx context.Context, network, address string) (stdnet.Conn, error) {
	// The mieru mux will request a connection toward the server address it has
	// recorded internally. We always route to the configured xray server
	// destination so transport-level features (TLS, routing) apply normally.
	dest := d.server
	dest.Network = net.Network_TCP
	if host, portStr, err := stdnet.SplitHostPort(address); err == nil {
		if p, perr := strconv.Atoi(portStr); perr == nil && p > 0 && p <= 0xFFFF {
			parsed := net.ParseAddress(host)
			if parsed != nil && (parsed.Family().IsIP() || parsed.Family().IsDomain()) {
				dest = net.Destination{
					Network: net.Network_TCP,
					Address: parsed,
					Port:    net.Port(p),
				}
			}
		}
	}
	id := d.get()
	if id == nil {
		return nil, errors.New("xray dialer is not bound to mieru client")
	}
	return id.Dial(ctx, dest)
}

// xrayPacketDialer adapts xray's internet.Dialer to mieru's PacketDialer.
type xrayPacketDialer struct {
	dialerHolder atomic.Pointer[internet.Dialer]
	server       net.Destination
}

func (d *xrayPacketDialer) set(id internet.Dialer) {
	d.dialerHolder.Store(&id)
}

func (d *xrayPacketDialer) get() internet.Dialer {
	p := d.dialerHolder.Load()
	if p == nil {
		return nil
	}
	return *p
}

var _ apicommon.PacketDialer = (*xrayPacketDialer)(nil)

func (d *xrayPacketDialer) ListenPacket(ctx context.Context, network, laddr, raddr string) (stdnet.PacketConn, error) {
	dest := d.server
	dest.Network = net.Network_UDP
	if raddr != "" {
		if host, portStr, err := stdnet.SplitHostPort(raddr); err == nil {
			if p, perr := strconv.Atoi(portStr); perr == nil && p > 0 && p <= 0xFFFF {
				parsed := net.ParseAddress(host)
				if parsed != nil && (parsed.Family().IsIP() || parsed.Family().IsDomain()) {
					dest = net.Destination{
						Network: net.Network_UDP,
						Address: parsed,
						Port:    net.Port(p),
					}
				}
			}
		}
	}
	id := d.get()
	if id == nil {
		return nil, errors.New("xray dialer is not bound to mieru client")
	}
	conn, err := id.Dial(ctx, dest)
	if err != nil {
		return nil, err
	}
	return &packetConnAdapter{Conn: conn, raddr: conn.RemoteAddr()}, nil
}

// packetConnAdapter wraps a connected udp net.Conn as a net.PacketConn so it
// satisfies the mieru PacketDialer return type. Mieru uses ReadFrom/WriteTo
// against the single remote that we connected to.
type packetConnAdapter struct {
	stdnet.Conn
	raddr stdnet.Addr
}

var _ stdnet.PacketConn = (*packetConnAdapter)(nil)

func (p *packetConnAdapter) ReadFrom(b []byte) (int, stdnet.Addr, error) {
	n, err := p.Conn.Read(b)
	return n, p.raddr, err
}

func (p *packetConnAdapter) WriteTo(b []byte, _ stdnet.Addr) (int, error) {
	return p.Conn.Write(b)
}

// toMieruAddr converts an xray Destination into a mieru NetAddrSpec.
func toMieruAddr(target net.Destination) stdnet.Addr {
	addr := model.AddrSpec{Port: int(target.Port)}
	switch target.Address.Family() {
	case net.AddressFamilyIPv4, net.AddressFamilyIPv6:
		addr.IP = stdnet.IP(target.Address.IP())
	default:
		addr.FQDN = target.Address.Domain()
	}
	network := "tcp"
	if target.Network == net.Network_UDP {
		network = "udp"
	}
	return model.NetAddrSpec{AddrSpec: addr, Net: network}
}

func parseTransportProtocol(s string) (appctlpb.TransportProtocol, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "", "TCP":
		return appctlpb.TransportProtocol_TCP, nil
	case "UDP":
		return appctlpb.TransportProtocol_UDP, nil
	default:
		return 0, errors.New("unknown mieru transport: ", s)
	}
}

func parseMultiplexingLevel(s string) (appctlpb.MultiplexingLevel, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "", "DEFAULT":
		return appctlpb.MultiplexingLevel_MULTIPLEXING_DEFAULT, false
	case "OFF":
		return appctlpb.MultiplexingLevel_MULTIPLEXING_OFF, true
	case "LOW":
		return appctlpb.MultiplexingLevel_MULTIPLEXING_LOW, true
	case "MIDDLE", "MID":
		return appctlpb.MultiplexingLevel_MULTIPLEXING_MIDDLE, true
	case "HIGH":
		return appctlpb.MultiplexingLevel_MULTIPLEXING_HIGH, true
	default:
		return appctlpb.MultiplexingLevel_MULTIPLEXING_DEFAULT, false
	}
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}
