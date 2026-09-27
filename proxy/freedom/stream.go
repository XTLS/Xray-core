package freedom

import (
	"context"
	"io"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/exchange"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// openConnection is the single Freedom policy, dial and PROXY-header preparation
// path used by both the old Link caller and ordinary stream admission.
func (h *Handler) openConnection(ctx context.Context, dialer internet.Dialer, destination net.Destination, defaultRule *FinalRule, outGateway net.Address, inbound *session.Inbound) (conn stat.Connection, blockedRule *FinalRule, blockedDest *net.Destination, err error) {
	err = retry.ExponentialBackoffContext(ctx, 5, 100).On(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if destination.Address.Family().IsDomain() {
			if defaultRule != nil || len(h.finalRules) > 0 {
				if strategy := h.resolveStrategy; strategy.HasStrategy() {
					ips, err := internet.LookupForIP(destination.Address.Domain(), strategy, outGateway)
					if err != nil { // non-force may still dial with system DNS
						errors.LogInfoInner(ctx, err, "failed to get IP address for domain ", destination.Address.Domain())
						if strategy.ForceIP() {
							return err // retry
						}
					}
					for _, ip := range ips {
						if addr := net.IPAddress(ip); addr != nil {
							if rule := h.matchFinalRule(destination.Network, addr, destination.Port, defaultRule); rule != nil && rule.action == RuleAction_Block {
								blockedDest = &destination
								blockedDest.Address = addr
								blockedRule = rule
								return nil
							}
						}
					}
				} else {
					addrs, err := net.DefaultResolver.LookupIPAddr(ctx, destination.Address.Domain())
					if err != nil { // dialer may retry DNS
						errors.LogInfoInner(ctx, err, "failed to get IP address for domain ", destination.Address.Domain())
					}
					for _, addr := range addrs {
						if ipAddr := net.IPAddress(addr.IP); ipAddr != nil {
							if rule := h.matchFinalRule(destination.Network, ipAddr, destination.Port, defaultRule); rule != nil && rule.action == RuleAction_Block {
								blockedDest = &destination
								blockedDest.Address = ipAddr
								blockedRule = rule
								return nil
							}
						}
					}
				}
			}
		} else {
			if rule := h.matchFinalRule(destination.Network, destination.Address, destination.Port, defaultRule); rule != nil && rule.action == RuleAction_Block {
				blockedDest = &destination
				blockedRule = rule
				return nil
			}
		}

		rawConn, err := dialer.Dial(ctx, destination)
		if err != nil {
			return err
		}

		conn = rawConn
		return nil
	})
	if err != nil {
		return nil, nil, nil, errors.New("failed to open connection to ", destination).Base(err)
	}
	if blockedDest != nil {
		return nil, blockedRule, blockedDest, nil
	}
	ownedConn := conn
	stopClose := context.AfterFunc(ctx, func() { _ = ownedConn.Close() })
	defer stopClose()
	if destination.Address.Family().IsDomain() && (defaultRule != nil || len(h.finalRules) > 0) {
		// pre-check may fail or dialer may select another IP
		remoteDest := net.DestinationFromAddr(conn.RemoteAddr())
		if rule := h.matchFinalRule(remoteDest.Network, remoteDest.Address, remoteDest.Port, defaultRule); rule != nil && rule.action == RuleAction_Block {
			conn.Close()
			return nil, rule, &remoteDest, nil
		}
	}

	if h.config.ProxyProtocol > 0 && h.config.ProxyProtocol <= 2 {
		version := byte(h.config.ProxyProtocol)
		srcAddr := inbound.Source.RawNetAddr()
		dstAddr := conn.RemoteAddr()
		header := proxyproto.HeaderProxyFromAddrs(version, srcAddr, dstAddr)
		if _, err = header.WriteTo(conn); err != nil {
			conn.Close()
			return nil, nil, nil, errors.New("failed to set PROXY protocol v", version).Base(err)
		}
	}
	if err := ctx.Err(); err != nil {
		_ = ownedConn.Close()
		return nil, nil, nil, err
	}
	return conn, nil, nil, nil
}

// PrepareStream hands over a fully opened TCP endpoint. The selected stream
// cohort does not interpret a blocked final-rule outcome as an outbound socket.
func (h *Handler) PrepareStream(ctx context.Context, source *exchange.Stream, dialer internet.Dialer) (exchange.Stream, error) {
	ob := session.OutboundsFromContext(ctx)
	target := ob[len(ob)-1]
	if !target.Target.IsValid() || target.Target.Network != net.Network_TCP {
		return exchange.Stream{}, errors.New("invalid freedom stream target")
	}
	target.Name, target.CanSpliceCopy = "freedom", 1
	inbound := session.InboundFromContext(ctx)
	var defaultRule *FinalRule
	if !h.usesDialerProxy {
		defaultRule = getDefaultFinalRule(inbound)
	}
	destination := target.Target
	if h.config.DestinationOverride != nil {
		server := h.config.DestinationOverride.Server
		if isValidAddress(server.Address) {
			destination.Address = server.Address.AsAddress()
		}
		if server.Port != 0 {
			destination.Port = net.Port(server.Port)
		}
	}
	dialer.SetOutboundGateway(ctx, target)
	conn, blockedRule, blocked, err := h.openConnection(ctx, dialer, destination, defaultRule, target.Gateway, inbound)
	if err != nil {
		return exchange.Stream{}, err
	}
	if blocked != nil {
		return exchange.Stream{}, exchange.Discard(*source, h.blockDelay(blockedRule))
	}
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return exchange.Stream{}, err
	}
	rawConn := stat.TryUnwrapStatsConn(conn)
	_, rawTCP := rawConn.(*net.TCPConn)
	var writer io.Writer = rawConn
	if h.config.Fragment != nil {
		writer = &FragmentWriter{fragment: h.config.Fragment, writer: rawConn}
	}
	stream := exchange.Stream{Reader: rawConn, Writer: writer, Abort: func() { _ = conn.Close() }, NativeRead: rawTCP, NativeWrite: rawTCP && h.config.Fragment == nil}
	stream.Splice = useSplice.Load()
	if statsConn, ok := conn.(*stat.CounterConnection); ok {
		if statsConn.ReadCounter != nil {
			stream.CountRead = func(n int64) { statsConn.ReadCounter.Add(n) }
		}
		if statsConn.WriteCounter != nil {
			stream.CountWrite = func(n int64) { statsConn.WriteCounter.Add(n) }
		}
	}
	if half, ok := rawConn.(interface{ CloseRead() error }); ok {
		stream.CloseRead = half.CloseRead
	}
	if half, ok := rawConn.(interface{ CloseWrite() error }); ok {
		stream.CloseWrite = half.CloseWrite
	}
	timeouts := h.policy().Timeouts
	stream.Policy = &timeouts
	return stream, nil
}
