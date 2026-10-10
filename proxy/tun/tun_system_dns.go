//go:build (linux && !android) || freebsd

package tun

import (
	"context"
	"net/netip"

	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	feature_dns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/dns/localdns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	routingsession "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/proxy/dns"
)

// probeSourcePort is a representative client port for the routing probe. A real
// query arrives from an ephemeral port that cannot be known in advance, so this
// only matters for a rule that matches on a source port.
const probeSourcePort = 49152

// verifyDNSRouting reports whether a DNS query to address would actually be
// handled. Redirecting the system resolver at an address nothing answers would
// break name resolution outright, so the takeover only proceeds when routing
// hands such a query to a DNS-capable outbound.
//
// Overridable for tests.
var verifyDNSRouting = func(ctx context.Context, inboundTag, source, address string) error {
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return errors.New("invalid DNS address ", address).Base(err)
	}
	src, err := netip.ParseAddr(source)
	if err != nil || src.Is4() != ip.Is4() {
		return errors.New("invalid source address ", source).Base(err)
	}

	instance := core.MustFromContext(ctx)

	// Any resolution path that could still reach the system resolver has to be
	// refused, because pointing the system resolver at the TUN would close a
	// loop through the DNS outbound. With no `dns` section Core installs such a
	// client; with a `dns` section that has no name servers app/dns falls back
	// to one; and a name server pointed at "localhost" is one even when
	// independent upstreams are configured alongside it, because name servers
	// are selected per domain.
	switch dnsFeature := instance.GetFeature(feature_dns.ClientType()).(type) {
	case *localdns.Client:
		return errors.New("DNS feature is the system resolver, takeover would loop")
	case *appdns.DNS:
		if dnsFeature.MayUseSystemResolver() {
			return errors.New("DNS configuration may resolve through the system resolver, takeover would loop")
		}
	}

	router, ok := instance.GetFeature(routing.RouterType()).(routing.Router)
	if !ok {
		return errors.New("router feature unavailable")
	}

	// A real query from this interface carries a source address, and rules may
	// match on it, so the probe has to carry one too.
	queryCtx := session.ContextWithInbound(ctx, &session.Inbound{
		Name:   "tun",
		Tag:    inboundTag,
		Source: xnet.UDPDestination(xnet.IPAddress(src.AsSlice()), probeSourcePort),
	})
	queryCtx = session.ContextWithOutbounds(queryCtx, []*session.Outbound{{
		Target: xnet.UDPDestination(xnet.IPAddress(ip.AsSlice()), 53),
	}})

	route, err := router.PickRoute(routingsession.AsRoutingContext(queryCtx))
	if err != nil {
		return errors.New("no route for ", address, ":53").Base(err)
	}

	manager, ok := instance.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if !ok {
		return errors.New("outbound manager unavailable")
	}

	handler := manager.GetHandler(route.GetOutboundTag())
	if handler == nil {
		return errors.New("outbound ", route.GetOutboundTag(), " does not exist")
	}
	if settings := handler.ProxySettings(); settings == nil || settings.Type != serial.GetMessageType(&dns.Config{}) {
		return errors.New("outbound ", route.GetOutboundTag(), " does not handle DNS")
	}
	return nil
}
