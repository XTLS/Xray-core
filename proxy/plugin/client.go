package plugin

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type Client struct {
	name   string
	params string
}

func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	var tag string
	if handler := session.FullHandlerFromContext(ctx); handler != nil {
		tag = handler.Tag()
	}
	TriggerOnPluginRegistered(tag, config.Name, config.Params)

	return &Client{
		name:   config.Name,
		params: config.Params,
	}, nil
}

type sizeStatReader struct {
	buf.Reader
	counter stats.Counter
}

func (r *sizeStatReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if r.counter != nil {
		r.counter.Add(int64(mb.Len()))
	}
	return mb, err
}

type sizeStatWriter struct {
	buf.Writer
	counter stats.Counter
}

func (w *sizeStatWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if w.counter != nil {
		w.counter.Add(int64(mb.Len()))
	}
	return w.Writer.WriteMultiBuffer(mb)
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified.")
	}
	destination := ob.Target

	handlerFunc := GetHandler(c.name)
	if handlerFunc == nil {
		return errors.New("plugin outbound handler not registered: ", c.name)
	}

	var tag string
	if len(outbounds) > 0 {
		tag = outbounds[len(outbounds)-1].Tag
	}
	if len(tag) > 0 {
		if v := core.FromContext(ctx); v != nil {
			if pmFeature := v.GetFeature(policy.ManagerType()); pmFeature != nil {
				if pm, ok := pmFeature.(policy.Manager); ok {
					if smFeature := v.GetFeature(stats.ManagerType()); smFeature != nil {
						if sm, ok := smFeature.(stats.Manager); ok {
							var uplinkCounter stats.Counter
							var downlinkCounter stats.Counter
							if pm.ForSystem().Stats.OutboundUplink {
								name := "outbound>>>" + tag + ">>>traffic>>>uplink"
								if c, err := stats.GetOrRegisterCounter(sm, name); err == nil && c != nil {
									uplinkCounter = c
								}
							}
							if pm.ForSystem().Stats.OutboundDownlink {
								name := "outbound>>>" + tag + ">>>traffic>>>downlink"
								if c, err := stats.GetOrRegisterCounter(sm, name); err == nil && c != nil {
									downlinkCounter = c
								}
							}
							if downlinkCounter != nil {
								link.Reader = &sizeStatReader{
									Reader:  link.Reader,
									counter: downlinkCounter,
								}
							}
							if uplinkCounter != nil {
								link.Writer = &sizeStatWriter{
									Writer:  link.Writer,
									counter: uplinkCounter,
								}
							}
						}
					}
				}
			}
		}
	}

	return handlerFunc(ctx, destination, link)
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}
