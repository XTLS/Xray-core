package loopback

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type Loopback struct {
	config             *Config
	dispatcherInstance routing.Dispatcher
}

func (l *Loopback) Process(ctx context.Context, link *transport.Link, _ internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified.")
	}
	ob.Name = "loopback"
	destination := ob.Target

	errors.LogInfo(ctx, "opening connection to ", destination)
	content := new(session.Content)
	content.SkipDNSResolve = true

	ctx = session.ContextWithContent(ctx, content)
	inbound := &session.Inbound{}
	originInbound := session.InboundFromContext(ctx)
	if originInbound != nil {
		// get a shallow copy to avoid modifying the inbound tag in upstream context
		*inbound = *originInbound
	}
	inbound.Tag = l.config.InboundTag
	ctx = session.ContextWithInbound(ctx, inbound)

	err := l.dispatcherInstance.DispatchLink(ctx, destination, link)
	if err != nil {
		errors.New(ctx, "failed to process loopback connection").Base(err)
		return err
	}
	return nil
}

func (l *Loopback) init(config *Config, dispatcherInstance routing.Dispatcher) error {
	l.dispatcherInstance = dispatcherInstance
	l.config = config
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
