package outbound_test

import (
	"context"
	"testing"

	"github.com/4nd3r5on/Xray-core/app/policy"
	"github.com/4nd3r5on/Xray-core/app/proxyman"
	. "github.com/4nd3r5on/Xray-core/app/proxyman/outbound"
	"github.com/4nd3r5on/Xray-core/app/stats"
	"github.com/4nd3r5on/Xray-core/common/net"
	"github.com/4nd3r5on/Xray-core/common/serial"
	core "github.com/4nd3r5on/Xray-core/core"
	"github.com/4nd3r5on/Xray-core/features/outbound"
	"github.com/4nd3r5on/Xray-core/proxy/freedom"
	"github.com/4nd3r5on/Xray-core/transport/internet/stat"
)

func TestInterfaces(t *testing.T) {
	_ = (outbound.Handler)(new(Handler))
	_ = (outbound.Manager)(new(Manager))
}

const xrayKey core.XrayKey = 1

func TestOutboundWithoutStatCounter(t *testing.T) {
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&policy.Config{
				System: &policy.SystemPolicy{
					Stats: &policy.SystemPolicy_Stats{
						InboundUplink: true,
					},
				},
			}),
		},
	}

	v, _ := core.New(config)
	v.AddFeature((outbound.Manager)(new(Manager)))
	ctx := context.WithValue(context.Background(), xrayKey, v)
	h, _ := NewHandler(ctx, &proxyman.OutboundHandlerConfig{
		Tag:           "tag",
		ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
	})
	conn, _ := h.(*Handler).Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), 13146))
	_, ok := conn.(*stat.CounterConnection)
	if ok {
		t.Errorf("Expected conn to not be CounterConnection")
	}
}

func TestOutboundWithStatCounter(t *testing.T) {
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&policy.Config{
				System: &policy.SystemPolicy{
					Stats: &policy.SystemPolicy_Stats{
						OutboundUplink:   true,
						OutboundDownlink: true,
					},
				},
			}),
		},
	}

	v, _ := core.New(config)
	v.AddFeature((outbound.Manager)(new(Manager)))
	ctx := context.WithValue(context.Background(), xrayKey, v)
	h, _ := NewHandler(ctx, &proxyman.OutboundHandlerConfig{
		Tag:           "tag",
		ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
	})
	conn, _ := h.(*Handler).Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), 13146))
	_, ok := conn.(*stat.CounterConnection)
	if !ok {
		t.Errorf("Expected conn to be CounterConnection")
	}
}
