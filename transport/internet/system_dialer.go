package internet

import (
	"context"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

var (
	effectiveSystemDialer SystemDialer = &DefaultSystemDialer{}
)

// InitSystemDialer: It's private method and you are NOT supposed to use this function.
func InitSystemDialer(dc dns.Client, om outbound.Manager) {
	effectiveSystemDialer.Init(dc, om)
}

type SystemDialer interface {
	Dial(ctx context.Context, source net.Address, destination net.Destination, sockopt *SocketConfig) (net.Conn, error)
	Init(dc dns.Client, om outbound.Manager)
}

type DefaultSystemDialer struct {
	controllers []controller
	dns         dns.Client
	obm         outbound.Manager
}

func resolveSrcAddr(network net.Network, src net.Address) net.Addr {
	if src == nil || src == net.AnyIP {
		return nil
	}

	if network == net.Network_TCP {
		return &net.TCPAddr{
			IP:   src.IP(),
			Port: 0,
		}
	}

	return &net.UDPAddr{
		IP:   src.IP(),
		Port: 0,
	}
}

func hasBindAddr(sockopt *SocketConfig) bool {
	return sockopt != nil && len(sockopt.BindAddress) > 0 && sockopt.BindPort > 0
}

func (d *DefaultSystemDialer) lookupIP(domain string, strategy DomainStrategy, localAddr net.Address) ([]net.IP, error) {
	if d.dns == nil {
		return nil, nil
	}

	var option = dns.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
		FakeEnable: false,
	}

	switch {
	case strategy == DomainStrategy_USE_IP4 || (localAddr != nil && localAddr.Family().IsIPv4()):
		option = dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: false,
			FakeEnable: false,
		}
	case strategy == DomainStrategy_USE_IP6 || (localAddr != nil && localAddr.Family().IsIPv6()):
		option = dns.IPOption{
			IPv4Enable: false,
			IPv6Enable: true,
			FakeEnable: false,
		}
	case strategy == DomainStrategy_AS_IS:
		return nil, nil
	}

	return d.dns.LookupIP(domain, option)
}

func (d *DefaultSystemDialer) canLookupIP(ctx context.Context, dst net.Destination, sockopt *SocketConfig) bool {
	if sockopt == nil || dst.Address.Family().IsIP() || d.dns == nil {
		return false
	}
	if dst.Address.Domain() == LookupDomainFromContext(ctx) {
		newError("infinite loop detected").AtError().WriteToLog(session.ExportIDToError(ctx))
		return false
	}
	return sockopt.DomainStrategy != DomainStrategy_AS_IS
}

func (d *DefaultSystemDialer) redirect(ctx context.Context, dst net.Destination, obt string) net.Conn {
	newError("redirecting request " + dst.String() + " to " + obt).WriteToLog(session.ExportIDToError(ctx))
	h := d.obm.GetHandler(obt)
	ctx = session.ContextWithOutbound(ctx, &session.Outbound{dst, nil})
	if h != nil {
		ur, uw := pipe.New(pipe.OptionsFromContext(ctx)...)
		dr, dw := pipe.New(pipe.OptionsFromContext(ctx)...)

		go h.Dispatch(ctx, &transport.Link{ur, dw})
		nc := cnc.NewConnection(
			cnc.ConnectionInputMulti(uw),
			cnc.ConnectionOutputMulti(dr),
			cnc.ConnectionOnClose(common.ChainedClosable{uw, dw}),
		)
		return nc
	}
	return nil
}

func (d *DefaultSystemDialer) Dial(ctx context.Context, src net.Address, dest net.Destination, sockopt *SocketConfig) (net.Conn, error) {
	newError("dialing to " + dest.String()).AtDebug().WriteToLog()
	if d.obm != nil && sockopt != nil && len(sockopt.DialerProxy) > 0 {
		nc := d.redirect(ctx, dest, sockopt.DialerProxy)
		if nc != nil {
			return nc, nil
		}
	}

	if d.canLookupIP(ctx, dest, sockopt) {
		ips, err := d.lookupIP(dest.Address.String(), sockopt.DomainStrategy, src)
		if err == nil && len(ips) > 0 {
			dest.Address = net.IPAddress(ips[dice.Roll(len(ips))])
			newError("replace destination with " + dest.String()).AtInfo().WriteToLog()
		} else if err != nil {
			newError("failed to resolve ip").Base(err).AtWarning().WriteToLog()
		}
	}

	if dest.Network == net.Network_UDP && !hasBindAddr(sockopt) {
		srcAddr := resolveSrcAddr(net.Network_UDP, src)
		if srcAddr == nil {
			srcAddr = &net.UDPAddr{
				IP:   []byte{0, 0, 0, 0},
				Port: 0,
			}
		}
		packetConn, err := ListenSystemPacket(ctx, srcAddr, sockopt)
		if err != nil {
			return nil, err
		}
		destAddr, err := net.ResolveUDPAddr("udp", dest.NetAddr())
		if err != nil {
			return nil, err
		}
		return &PacketConnWrapper{
			conn: packetConn,
			dest: destAddr,
		}, nil
	}

	dialer := &net.Dialer{
		Timeout:   time.Second * 16,
		DualStack: true,
		LocalAddr: resolveSrcAddr(dest.Network, src),
	}

	if sockopt != nil || len(d.controllers) > 0 {
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if sockopt != nil {
					if err := applyOutboundSocketOptions(network, address, fd, sockopt); err != nil {
						newError("failed to apply socket options").Base(err).WriteToLog(session.ExportIDToError(ctx))
					}
					if dest.Network == net.Network_UDP && hasBindAddr(sockopt) {
						if err := bindAddr(fd, sockopt.BindAddress, sockopt.BindPort); err != nil {
							newError("failed to bind source address to ", sockopt.BindAddress).Base(err).WriteToLog(session.ExportIDToError(ctx))
						}
					}
				}

				for _, ctl := range d.controllers {
					if err := ctl(network, address, fd); err != nil {
						newError("failed to apply external controller").Base(err).WriteToLog(session.ExportIDToError(ctx))
					}
				}
			})
		}
	}

	return dialer.DialContext(ctx, dest.Network.SystemString(), dest.NetAddr())
}

func (d *DefaultSystemDialer) Init(dc dns.Client, om outbound.Manager) {
	d.dns = dc
	d.obm = om
}

type PacketConnWrapper struct {
	conn net.PacketConn
	dest net.Addr
}

func (c *PacketConnWrapper) Close() error {
	return c.conn.Close()
}

func (c *PacketConnWrapper) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *PacketConnWrapper) RemoteAddr() net.Addr {
	return c.dest
}

func (c *PacketConnWrapper) Write(p []byte) (int, error) {
	return c.conn.WriteTo(p, c.dest)
}

func (c *PacketConnWrapper) Read(p []byte) (int, error) {
	n, _, err := c.conn.ReadFrom(p)
	return n, err
}

func (c *PacketConnWrapper) WriteTo(p []byte, d net.Addr) (int, error) {
	return c.conn.WriteTo(p, d)
}

func (c *PacketConnWrapper) ReadFrom(p []byte) (int, net.Addr, error) {
	return c.conn.ReadFrom(p)
}

func (c *PacketConnWrapper) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *PacketConnWrapper) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *PacketConnWrapper) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

type SystemDialerAdapter interface {
	Dial(network string, address string) (net.Conn, error)
}

type SimpleSystemDialer struct {
	adapter SystemDialerAdapter
}

func WithAdapter(dialer SystemDialerAdapter) SystemDialer {
	return &SimpleSystemDialer{
		adapter: dialer,
	}
}

func (v *SimpleSystemDialer) Init(_ dns.Client, _ outbound.Manager) {}

func (v *SimpleSystemDialer) Dial(ctx context.Context, src net.Address, dest net.Destination, sockopt *SocketConfig) (net.Conn, error) {
	return v.adapter.Dial(dest.Network.SystemString(), dest.NetAddr())
}

// UseAlternativeSystemDialer replaces the current system dialer with a given one.
// Caller must ensure there is no race condition.
//
// xray:api:stable
func UseAlternativeSystemDialer(dialer SystemDialer) {
	if dialer == nil {
		effectiveSystemDialer = &DefaultSystemDialer{}
	}
	effectiveSystemDialer = dialer
}

// RegisterDialerController adds a controller to the effective system dialer.
// The controller can be used to operate on file descriptors before they are put into use.
// It only works when effective dialer is the default dialer.
//
// xray:api:beta
func RegisterDialerController(ctl func(network, address string, fd uintptr) error) error {
	if ctl == nil {
		return newError("nil listener controller")
	}

	dialer, ok := effectiveSystemDialer.(*DefaultSystemDialer)
	if !ok {
		return newError("RegisterListenerController not supported in custom dialer")
	}

	dialer.controllers = append(dialer.controllers, ctl)
	return nil
}
