package dispatcher

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/transport/exchange"
)

// DispatchStream admits one already decoded stream. Its caller retains custody
// of the source until this call returns; selected preparation takes ownership
// only when it returns a prepared endpoint.
func (d *DefaultDispatcher) DispatchStream(ctx context.Context, destination net.Destination, source exchange.Stream) error {
	if !destination.IsValid() || destination.Network != net.Network_TCP {
		return errors.New("invalid stream destination")
	}
	ctx, source, finish := exchange.Admit(ctx, source)
	defer finish()
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	ob := outbounds[len(outbounds)-1]
	ob.OriginalTarget, ob.Target = destination, destination
	content := session.ContentFromContext(ctx)
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
	}
	source = d.wrapStream(ctx, source)
	input := exchange.NewInput(source.Reader, source.SetReadDeadline)
	source.Reader = input
	if request := content.SniffingRequest; request.Enabled {
		var result SniffResult
		var err error
		result, err = d.sniffStream(ctx, input, request.MetadataOnly, destination.Network)
		if err == nil {
			content.Protocol = result.Protocol()
			if d.shouldOverride(ctx, result, request, destination) {
				domain := result.Domain()
				errors.LogInfo(ctx, "sniffed domain: ", domain)
				destination.Address = net.ParseAddress(domain)
				protocolName := result.Protocol()
				if composite, ok := result.(SnifferResultComposite); ok {
					protocolName = composite.ProtocolForDomainResult()
				}
				isFakeIP := false
				if fkr0, ok := d.fdns.(interface{ IsIPInIPPool(net.Address) bool }); ok && fkr0.IsIPInIPPool(ob.Target.Address) {
					isFakeIP = true
				}
				if request.RouteOnly && protocolName != "fakedns" && protocolName != "fakedns+others" && !isFakeIP {
					ob.RouteTarget = destination
				} else {
					ob.Target = destination
				}
			}
		}
	}
	ctx, handler, err := d.selectStreamHandler(ctx, destination)
	if err != nil {
		return err
	}
	return outbound.DispatchStream(handler, ctx, source)
}

func (d *DefaultDispatcher) sniffStream(ctx context.Context, input *exchange.Input, metadataOnly bool, network net.Network) (SniffResult, error) {
	sniffer := NewSniffer(ctx)
	metadata, metaErr := sniffer.SniffMetadata(ctx)
	if metadataOnly {
		return metadata, metaErr
	}
	deadline := time.Now().Add(200 * time.Millisecond)
	var content SniffResult
	var contentErr error
	noClue := 0
	for len(input.Peeked()) < 32767 {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			contentErr = errSniffingTimeout
			break
		}
		payload, readErr := input.PeekMore(32767, remaining)
		if len(payload) == 0 {
			contentErr = readErr
			if contentErr == nil {
				contentErr = errSniffingTimeout
			}
			break
		}
		content, contentErr = sniffer.Sniff(ctx, payload, network)
		if contentErr == common.ErrNoClue {
			noClue++
		} else if contentErr != protocol.ErrProtoNeedMoreData {
			break
		}
		if noClue >= 2 || readErr != nil {
			break
		}
	}
	if contentErr != nil && metaErr == nil {
		return metadata, nil
	}
	if contentErr == nil && metaErr == nil {
		return CompositeResult(metadata, content), nil
	}
	return content, contentErr
}

func (d *DefaultDispatcher) wrapStream(ctx context.Context, source exchange.Stream) exchange.Stream {
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

func chainCount(previous, next func(int64)) func(int64) {
	if previous == nil {
		return next
	}
	return func(n int64) { previous(n); next(n) }
}

// selectStreamHandler shares the native router and manager. The old Link
// entrance retains its own selection until the remaining callers are moved.
func (d *DefaultDispatcher) selectStreamHandler(ctx context.Context, destination net.Destination) (context.Context, outbound.Handler, error) {
	routingLink := routing_session.AsRoutingContext(ctx)
	inTag := routingLink.GetInboundTag()
	isPickRoute := 0
	var handler outbound.Handler
	if forcedTag := session.GetForcedOutboundTagFromContext(ctx); forcedTag != "" {
		ctx = session.SetForcedOutboundTagToContext(ctx, "")
		handler = d.ohm.GetHandler(forcedTag)
		if handler == nil {
			return ctx, nil, errors.New("non existing tag for platform initialized detour: ", forcedTag)
		}
		isPickRoute = 1
		errors.LogInfo(ctx, "taking platform initialized detour [", forcedTag, "] for [", destination, "]")
	} else if d.router != nil {
		if route, err := d.router.PickRoute(routingLink); err == nil {
			outTag := route.GetOutboundTag()
			handler = d.ohm.GetHandler(outTag)
			if handler == nil {
				return ctx, nil, errors.New("non existing outTag: ", outTag)
			}
			isPickRoute = 2
			if route.GetRuleTag() == "" {
				errors.LogInfo(ctx, "taking detour [", outTag, "] for [", destination, "]")
			} else {
				errors.LogInfo(ctx, "Hit route rule: [", route.GetRuleTag(), "] so taking detour [", outTag, "] for [", destination, "]")
			}
		} else {
			errors.LogInfo(ctx, "default route for ", destination)
		}
	}
	if handler == nil {
		handler = d.ohm.GetDefaultHandler()
	}
	if handler == nil {
		return ctx, nil, errors.New("default outbound handler not exist")
	}
	ob := session.OutboundsFromContext(ctx)
	ob[len(ob)-1].Tag = handler.Tag()
	if access := log.AccessMessageFromContext(ctx); access != nil {
		if tag := handler.Tag(); tag != "" {
			switch {
			case inTag == "":
				access.Detour = tag
			case isPickRoute == 1:
				access.Detour = inTag + " ==> " + tag
			case isPickRoute == 2:
				access.Detour = inTag + " -> " + tag
			default:
				access.Detour = inTag + " >> " + tag
			}
		}
		log.Record(access)
	}
	return ctx, handler, nil
}
