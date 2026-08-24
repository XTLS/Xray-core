package inbound_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	core "github.com/xtls/xray-core/core"
	featureinbound "github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria"
	"github.com/xtls/xray-core/transport/internet/kcp"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestSourceAwareMixedTCPUDPRejectedBeforeHandlerRegistration(t *testing.T) {
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				Tag: "mixed-source-aware",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(24443)}},
					StreamSettings: &internet.StreamConfig{
						ProtocolName: "tcp",
						TransportSettings: []*internet.TransportConfig{
							{ProtocolName: "tcp", Settings: serial.ToTypedMessage(&tcp.Config{})},
						},
						SocketSettings: &internet.SocketConfig{
							ProxyProtocolMode:           internet.SocketConfig_ProxyProtocolTrustedSources,
							ProxyProtocolTrustedSources: []string{"192.0.2.10"},
						},
					},
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					RewriteAddress:  net.NewIPOrDomain(net.LocalHostIP),
					RewritePort:     80,
					AllowedNetworks: []net.Network{net.Network_TCP, net.Network_UDP},
				}),
			},
		},
	}

	instance, err := core.New(config)
	if instance != nil {
		_ = instance.Close()
	}
	if err == nil {
		t.Fatal("mixed TCP/UDP source-aware inbound was registered")
	}
}

func TestSourceAwarePacketTransportsRejectedBeforeHandlerRegistration(t *testing.T) {
	h3TLS := serial.ToTypedMessage(&tls.Config{NextProtocol: []string{"h3"}})
	tests := []struct {
		name   string
		stream *internet.StreamConfig
	}{
		{
			name:   "mKCP",
			stream: sourceAwareStream("mkcp", serial.ToTypedMessage(&kcp.Config{})),
		},
		{
			name:   "Hysteria",
			stream: sourceAwareStream("hysteria", serial.ToTypedMessage(&hysteria.Config{Auth: "test"})),
		},
		{
			name: "XHTTP H3",
			stream: func() *internet.StreamConfig {
				stream := sourceAwareStream("splithttp", serial.ToTypedMessage(&splithttp.Config{}))
				stream.SecurityType = h3TLS.Type
				stream.SecuritySettings = []*serial.TypedMessage{h3TLS}
				return stream
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instance, err := core.New(&core.Config{
				App:     []*serial.TypedMessage{serial.ToTypedMessage(&proxyman.InboundConfig{})},
				Inbound: []*core.InboundHandlerConfig{sourceAwareInbound("packet-source-aware", test.stream)},
			})
			if instance != nil {
				_ = instance.Close()
			}
			if err == nil {
				t.Fatal("packet-based source-aware transport passed core.New")
			}
		})
	}
}

func TestSourceAwarePacketTransportHotAddDoesNotRegisterHandler(t *testing.T) {
	instance, err := core.New(&core.Config{
		App: []*serial.TypedMessage{serial.ToTypedMessage(&proxyman.InboundConfig{})},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}

	const tag = "hot-mkcp-source-aware"
	config := sourceAwareInbound(tag, sourceAwareStream("mkcp", serial.ToTypedMessage(&kcp.Config{})))
	if err := core.AddInboundHandler(instance, config); err == nil {
		t.Fatal("hot AddInbound accepted packet-based source-aware transport")
	}

	manager := instance.GetFeature(featureinbound.ManagerType()).(featureinbound.Manager)
	if _, err := manager.GetHandler(context.Background(), tag); err == nil {
		t.Fatal("failed hot AddInbound left its handler registered")
	}
}

func sourceAwareStream(protocol string, settings *serial.TypedMessage) *internet.StreamConfig {
	return &internet.StreamConfig{
		ProtocolName: protocol,
		TransportSettings: []*internet.TransportConfig{
			{ProtocolName: protocol, Settings: settings},
		},
		SocketSettings: &internet.SocketConfig{
			ProxyProtocolMode:           internet.SocketConfig_ProxyProtocolTrustedSources,
			ProxyProtocolTrustedSources: []string{"192.0.2.10"},
		},
	}
}

func sourceAwareInbound(tag string, stream *internet.StreamConfig) *core.InboundHandlerConfig {
	return &core.InboundHandlerConfig{
		Tag: tag,
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
			PortList:       &net.PortList{Range: []*net.PortRange{net.SinglePortRange(24443)}},
			StreamSettings: stream,
		}),
		ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
			RewriteAddress:  net.NewIPOrDomain(net.LocalHostIP),
			RewritePort:     80,
			AllowedNetworks: []net.Network{net.Network_TCP},
		}),
	}
}
