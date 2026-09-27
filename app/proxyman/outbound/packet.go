package outbound

import (
	"context"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	foutbound "github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport/exchange"
	"github.com/xtls/xray-core/transport/internet"
)

// PreparePacket retains the handler's sender strategy for one routed leg.
// Address translation stays on the prepared leg; the source is never wrapped.
func (h *Handler) PreparePacket(ctx context.Context) (exchange.PacketEndpoint, error) {
	ob := session.OutboundsFromContext(ctx)
	if len(ob) == 0 || ob[len(ob)-1].Target.Network != net.Network_UDP {
		return exchange.PacketEndpoint{}, errors.New("invalid outbound packet target")
	}
	if h.mux != nil && h.mux.Enabled {
		return exchange.PacketEndpoint{}, errors.New("MUX outbound packet association remains outside this admission")
	}
	current := ob[len(ob)-1]
	original := current.OriginalTarget.Address
	content := session.ContentFromContext(ctx)
	if h.senderSettings != nil && h.senderSettings.TargetStrategy.HasStrategy() && current.Target.Address.Family().IsDomain() && (content == nil || !content.SkipDNSResolve) {
		strategy := h.senderSettings.TargetStrategy
		if original != nil {
			strategy = strategy.GetDynamicStrategy(original.Family())
		}
		ips, err := internet.LookupForIP(current.Target.Address.Domain(), strategy, nil)
		if err != nil || len(ips) == 0 {
			if h.senderSettings.TargetStrategy.ForceIP() {
				failure := errors.New("failed to resolve packet target ", current.Target.Address).Base(err)
				session.SubmitOutboundErrorToOriginator(ctx, failure)
				return exchange.PacketEndpoint{}, failure
			}
		} else {
			current.Target.Address = net.IPAddress(ips[dice.Roll(len(ips))])
		}
	}
	resolved := current.Target.Address
	var endpoint exchange.PacketEndpoint
	var err error
	if preparer, ok := h.proxy.(proxy.PacketOutbound); ok {
		endpoint, err = preparer.PreparePacket(ctx, h)
	} else {
		endpoint = foutbound.PrepareLegacyPacket(ctx, h, current.OriginalTarget)
	}
	if err != nil {
		if endpoint.Abort != nil {
			endpoint.Abort()
		}
		session.SubmitOutboundErrorToOriginator(ctx, err)
		return exchange.PacketEndpoint{}, err
	}
	if err := ctx.Err(); err != nil {
		if endpoint.Abort != nil {
			endpoint.Abort()
		}
		return exchange.PacketEndpoint{}, err
	}
	if endpoint.Reader == nil || endpoint.Writer == nil || endpoint.Abort == nil {
		if endpoint.Abort != nil {
			endpoint.Abort()
		}
		return exchange.PacketEndpoint{}, errors.New("invalid prepared packet endpoint")
	}
	if original != nil && original != resolved {
		endpoint.Writer = packetAddressWriter{PacketWriter: endpoint.Writer, from: original, to: resolved}
		endpoint.Reader = packetAddressReader{PacketReader: endpoint.Reader, from: resolved, to: original}
	}
	return endpoint, nil
}

type packetAddressReader struct {
	exchange.PacketReader
	from, to net.Address
}

func (r packetAddressReader) ReadPacket(p []byte) (int, net.Destination, error) {
	n, dest, err := r.PacketReader.ReadPacket(p)
	if dest.Address == r.from {
		dest.Address = r.to
	}
	return n, dest, err
}

type packetAddressWriter struct {
	exchange.PacketWriter
	from, to net.Address
}

func (w packetAddressWriter) WritePacket(p []byte, dest net.Destination) (int, error) {
	if dest.Address == w.from {
		dest.Address = w.to
	}
	return w.PacketWriter.WritePacket(p, dest)
}
