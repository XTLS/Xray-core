package loopback

import (
	"context"
	"slices"

	proxyman "github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type Loopback struct {
	inboundTag         string
	sniffingRequest    session.SniffingRequest
	dispatcherInstance routing.Dispatcher
}

type loopbackInboundTagHistoryKey struct{}

func hasLoopbackInboundTag(ctx context.Context, tag string) bool {
	tags, _ := ctx.Value(loopbackInboundTagHistoryKey{}).([]string)
	return slices.Contains(tags, tag)
}

func contextWithLoopbackInboundTag(ctx context.Context, tag string) context.Context {
	tags, _ := ctx.Value(loopbackInboundTagHistoryKey{}).([]string)
	nextTags := make([]string, 0, len(tags)+1)
	nextTags = append(nextTags, tags...)
	nextTags = append(nextTags, tag)
	return context.WithValue(ctx, loopbackInboundTagHistoryKey{}, nextTags)
}

func (l *Loopback) Process(ctx context.Context, link *transport.Link, _ internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified.")
	}
	ob.Name = "loopback"
	destination := ob.Target

	if hasLoopbackInboundTag(ctx, l.inboundTag) {
		return errors.New("loopback connection detected for inbound tag: ", l.inboundTag)
	}
	ctx = contextWithLoopbackInboundTag(ctx, l.inboundTag)

	errors.LogInfo(ctx, "opening connection to ", destination)
	content := new(session.Content)
	content.SkipDNSResolve = true
	content.SniffingRequest = l.sniffingRequest

	ctx = session.ContextWithContent(ctx, content)
	inbound := &session.Inbound{}
	originInbound := session.InboundFromContext(ctx)
	if originInbound != nil {
		// get a shallow copy to avoid modifying the inbound tag in upstream context
		*inbound = *originInbound
	}
	inbound.Tag = l.inboundTag
	ctx = session.ContextWithInbound(ctx, inbound)

	err := l.dispatcherInstance.DispatchLink(ctx, destination, link)
	if err != nil {
		return errors.New(ctx, "failed to process loopback connection").Base(err)
	}
	return nil
}

func (l *Loopback) init(config *Config, dispatcherInstance routing.Dispatcher) error {
	l.dispatcherInstance = dispatcherInstance
	l.inboundTag = config.InboundTag
	if config.Sniffing.GetEnabled() {
		request, err := proxyman.BuildSniffingRequest(config.Sniffing)
		if err != nil {
			return errors.New("failed to build loopback sniffing request").Base(err).AtError()
		}
		l.sniffingRequest = request
	}
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		l := new(Loopback)
		err := core.RequireFeatures(ctx, func(dispatcherInstance routing.Dispatcher) error {
			return l.init(config.(*Config), dispatcherInstance)
		})
		return l, err
	}))
}
