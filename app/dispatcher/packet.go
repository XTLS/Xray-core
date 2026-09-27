package dispatcher

import (
	"context"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport/exchange"
)

// DispatchPacket owns the SOCKS association. Every replacement leg receives
// fresh mutable routing metadata and passes through the native router again.
func (d *DefaultDispatcher) DispatchPacket(ctx context.Context, first net.Destination, source exchange.PacketEndpoint) error {
	if !first.IsValid() || first.Network != net.Network_UDP {
		return errors.New("invalid packet destination")
	}
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
	}
	template := *outbounds[len(outbounds)-1]
	content := session.ContentFromContext(ctx)
	var contentTemplate session.Content
	if content != nil {
		contentTemplate = *content
		if content.Attributes != nil {
			contentTemplate.Attributes = make(map[string]string, len(content.Attributes))
			for key, value := range content.Attributes {
				contentTemplate.Attributes[key] = value
			}
		}
	}
	source = d.wrapPacket(ctx, source)
	return exchange.RunPacketAssociation(ctx, source, func(legCtx context.Context, dest net.Destination) (exchange.PacketEndpoint, error) {
		fresh := template
		fresh.OriginalTarget, fresh.Target = dest, dest
		fresh.RouteTarget = net.Destination{}
		fresh.Tag = ""
		fresh.Name = ""
		fresh.CanSpliceCopy = 0
		legCtx = session.ContextWithOutbounds(legCtx, append(append([]*session.Outbound(nil), outbounds[:len(outbounds)-1]...), &fresh))
		legContent := contentTemplate
		if contentTemplate.Attributes != nil {
			legContent.Attributes = make(map[string]string, len(contentTemplate.Attributes))
			for key, value := range contentTemplate.Attributes {
				legContent.Attributes[key] = value
			}
		}
		legCtx = session.ContextWithContent(legCtx, &legContent)
		selectedCtx, handler, err := d.selectStreamHandler(legCtx, dest)
		if err != nil {
			return exchange.PacketEndpoint{}, err
		}
		packetHandler, ok := handler.(outbound.PacketHandler)
		if !ok {
			return outbound.PrepareLegacyPacket(selectedCtx, handler, dest), nil
		}
		return packetHandler.PreparePacket(selectedCtx)
	})
}

func (d *DefaultDispatcher) wrapPacket(ctx context.Context, source exchange.PacketEndpoint) exchange.PacketEndpoint {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || inbound.User == nil || inbound.User.Email == "" {
		return source
	}
	p := d.policy.ForLevel(inbound.User.Level)
	if p.Stats.UserUplink {
		if counter, _ := d.stats.GetOrRegisterCounter("user>>>" + inbound.User.Email + ">>>traffic>>>uplink"); counter != nil {
			source.CountRead = chainCount(source.CountRead, func(n int64) { counter.Add(n) })
		}
	}
	if p.Stats.UserDownlink {
		if counter, _ := d.stats.GetOrRegisterCounter("user>>>" + inbound.User.Email + ">>>traffic>>>downlink"); counter != nil {
			source.CountWrite = chainCount(source.CountWrite, func(n int64) { counter.Add(n) })
		}
	}
	if p.Stats.UserOnline && inbound.Source.IsValid() {
		trackOnlineIP(ctx, d.stats, inbound.User.Email, inbound.Source.Address.String())
	}
	return source
}
