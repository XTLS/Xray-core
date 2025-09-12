package dns

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
)

// ResolvableContext is an implementation of routing.Context, with domain resolving capability.
type ResolvableContext struct {
	routing.Context
	dnsClient   dns.Client
	resolvedIPs []net.IP
	lookupError error
}

// GetTargetIPs overrides original routing.Context's implementation.
func (ctx *ResolvableContext) GetTargetIPs() []net.IP {
	if len(ctx.resolvedIPs) > 0 {
		return ctx.resolvedIPs
	}

	if ips := ctx.Context.GetTargetIPs(); len(ips) != 0 {
		return ips
	}

	if domain := ctx.GetTargetDomain(); len(domain) != 0 {
		ips, _, err := ctx.dnsClient.LookupIP(domain, dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: true,
			FakeEnable: false,
		})
		if err == nil {
			ctx.resolvedIPs = ips
			return ips
		}
		ctx.lookupError = errors.New("resolve ip for ", domain).Base(err)
	}

	return nil
}

// GetError override original routing.Context's implementation.
func (ctx *ResolvableContext) GetError() error {
	return ctx.lookupError
}

// ContextWithDNSClient creates a new routing context with domain resolving capability.
// Resolved domain IPs can be retrieved by GetTargetIPs().
func ContextWithDNSClient(ctx routing.Context, client dns.Client) routing.Context {
	return &ResolvableContext{Context: ctx, dnsClient: client}
}
