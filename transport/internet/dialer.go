package internet

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

// Dialer is the interface for dialing outbound connections.
type Dialer interface {
	// Dial dials a system connection to the given destination.
	Dial(ctx context.Context, destination net.Destination) (stat.Connection, error)

	// Address returns the address used by this Dialer. Maybe nil if not known.
	Address() net.Address
}

// dialFunc is an interface to dial network connection to a specific destination.
type dialFunc func(ctx context.Context, dest net.Destination, streamSettings *MemoryStreamConfig) (stat.Connection, error)

var transportDialerCache = make(map[string]dialFunc)

// RegisterTransportDialer registers a Dialer with given name.
func RegisterTransportDialer(protocol string, dialer dialFunc) error {
	if _, found := transportDialerCache[protocol]; found {
		return newError(protocol, " dialer already registered").AtError()
	}
	transportDialerCache[protocol] = dialer
	return nil
}

// Dial dials a internet connection towards the given destination.
func Dial(ctx context.Context, dest net.Destination, streamSettings *MemoryStreamConfig) (stat.Connection, error) {
	if dest.Network == net.Network_TCP {
		if streamSettings == nil {
			s, err := ToMemoryStreamConfig(nil)
			if err != nil {
				return nil, newError("failed to create default stream settings").Base(err)
			}
			streamSettings = s
		}

		protocol := streamSettings.ProtocolName
		dialer := transportDialerCache[protocol]
		if dialer == nil {
			return nil, newError(protocol, " dialer not registered").AtError()
		}
		return dialer(ctx, dest, streamSettings)
	}

	if dest.Network == net.Network_UDP {
		udpDialer := transportDialerCache["udp"]
		if udpDialer == nil {
			return nil, newError("UDP dialer not registered").AtError()
		}
		return udpDialer(ctx, dest, streamSettings)
	}

	return nil, newError("unknown network ", dest.Network)
}

var (
	dnsClient dns.Client
	obm       outbound.Manager
)

func lookupIP(domain string, strategy DomainStrategy, localAddr net.Address) ([]net.IP, error) {
	if dnsClient == nil {
		return nil, nil
	}

	option := dns.IPOption{
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

	return dnsClient.LookupIP(domain, option)
}

func canLookupIP(ctx context.Context, dst net.Destination, sockopt *SocketConfig) bool {
	if dst.Address.Family().IsIP() || dnsClient == nil {
		return false
	}
	return sockopt.DomainStrategy != DomainStrategy_AS_IS
}

func redirect(ctx context.Context, dst net.Destination, obt string) net.Conn {
	newError("redirecting request " + dst.String() + " to " + obt).WriteToLog(session.ExportIDToError(ctx))
	h := obm.GetHandler(obt)
	ctx = session.ContextWithOutbound(ctx, &session.Outbound{Target: dst, Gateway: nil})
	if h != nil {
		ur, uw := pipe.New(pipe.OptionsFromContext(ctx)...)
		dr, dw := pipe.New(pipe.OptionsFromContext(ctx)...)

		go h.Dispatch(ctx, &transport.Link{Reader: ur, Writer: dw})
		nc := cnc.NewConnection(
			cnc.ConnectionInputMulti(uw),
			cnc.ConnectionOutputMulti(dr),
			cnc.ConnectionOnClose(common.ChainedClosable{uw, dw}),
		)
		return nc
	}
	return nil
}

// DialSystem calls system dialer to create a network connection.
func DialSystem(ctx context.Context, dest net.Destination, sockopt *SocketConfig) (net.Conn, error) {
	var src net.Address
	if outbound := session.OutboundFromContext(ctx); outbound != nil {
		src = outbound.Gateway
	}
	if sockopt == nil {
		return effectiveSystemDialer.Dial(ctx, src, dest, sockopt)
	}

	if canLookupIP(ctx, dest, sockopt) {
		ips, err := lookupIP(dest.Address.String(), sockopt.DomainStrategy, src)
		if err == nil && len(ips) > 0 {
			dest.Address = net.IPAddress(ips[dice.Roll(len(ips))])
			newError("replace destination with " + dest.String()).AtInfo().WriteToLog()
		} else if err != nil {
			newError("failed to resolve ip").Base(err).AtWarning().WriteToLog()
		}
	}

	if obm != nil && len(sockopt.DialerProxy) > 0 {
		nc := redirect(ctx, dest, sockopt.DialerProxy)
		if nc != nil {
			return nc, nil
		}
	}

	return effectiveSystemDialer.Dial(ctx, src, dest, sockopt)
}

func InitSystemDialer(dc dns.Client, om outbound.Manager) {
	dnsClient = dc
	obm = om
}
