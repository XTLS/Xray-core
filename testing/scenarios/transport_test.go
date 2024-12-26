package scenarios

import (
	"testing"
	"time"

	"github.com/GFW-knocker/Xray-core/app/proxyman"
	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/protocol"
	"github.com/GFW-knocker/Xray-core/common/serial"
	"github.com/GFW-knocker/Xray-core/common/uuid"
	"github.com/GFW-knocker/Xray-core/core"
	"github.com/GFW-knocker/Xray-core/proxy/dokodemo"
	"github.com/GFW-knocker/Xray-core/proxy/freedom"
	"github.com/GFW-knocker/Xray-core/proxy/vmess"
	"github.com/GFW-knocker/Xray-core/proxy/vmess/inbound"
	"github.com/GFW-knocker/Xray-core/proxy/vmess/outbound"
	"github.com/GFW-knocker/Xray-core/testing/servers/tcp"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	"github.com/GFW-knocker/Xray-core/transport/internet/headers/http"
	tcptransport "github.com/GFW-knocker/Xray-core/transport/internet/tcp"
)

func TestHTTPConnectionHeader(t *testing.T) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	userID := protocol.NewID(uuid.New())
	serverPort := tcp.PickPort()
	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
					StreamSettings: &internet.StreamConfig{
						TransportSettings: []*internet.TransportConfig{
							{
								ProtocolName: "tcp",
								Settings: serial.ToTypedMessage(&tcptransport.Config{
									HeaderSettings: serial.ToTypedMessage(&http.Config{}),
								}),
							},
						},
					},
				}),
				ProxySettings: serial.ToTypedMessage(&inbound.Config{
					User: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vmess.Account{
								Id: userID.String(),
							}),
						},
					},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
			},
		},
	}

	clientPort := tcp.PickPort()
	clientConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					Address:  net.NewIPOrDomain(dest.Address),
					Port:     uint32(dest.Port),
					Networks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&outbound.Config{
					Receiver: []*protocol.ServerEndpoint{
						{
							Address: net.NewIPOrDomain(net.LocalHostIP),
							Port:    uint32(serverPort),
							User: []*protocol.User{
								{
									Account: serial.ToTypedMessage(&vmess.Account{
										Id: userID.String(),
									}),
								},
							},
						},
					},
				}),
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: &internet.StreamConfig{
						TransportSettings: []*internet.TransportConfig{
							{
								ProtocolName: "tcp",
								Settings: serial.ToTypedMessage(&tcptransport.Config{
									HeaderSettings: serial.ToTypedMessage(&http.Config{}),
								}),
							},
						},
					},
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	if err := testTCPConn(clientPort, 1024, time.Second*2)(); err != nil {
		t.Error(err)
	}
}
