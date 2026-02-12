package scenarios

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/inbound"
	"github.com/xtls/xray-core/proxy/vmess/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	finalsudoku "github.com/xtls/xray-core/transport/internet/finalmask/sudoku"
	"github.com/xtls/xray-core/transport/internet/headers/http"
	tcptransport "github.com/xtls/xray-core/transport/internet/tcp"
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
					Receiver: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(serverPort),
						User: &protocol.User{
							Account: serial.ToTypedMessage(&vmess.Account{
								Id: userID.String(),
							}),
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

func TestSudokuTcpmaskBDD(t *testing.T) {
	cases := []struct {
		name string
		mask *finalsudoku.Config
	}{
		{
			name: "prefer-ascii",
			mask: &finalsudoku.Config{
				Password: "bdd-sudoku",
				Ascii:    "prefer_ascii",
			},
		},
		{
			name: "custom-table",
			mask: &finalsudoku.Config{
				Password:    "bdd-sudoku",
				Ascii:       "prefer_entropy",
				CustomTable: "xpxvvpvv",
			},
		},
	}

	for _, c := range cases {
		t.Run("GivenSudokuTcpmaskWhenRunningVmessOverTCPThenTrafficRoundTrips/"+c.name, func(t *testing.T) {
			tcpServer := tcp.Server{MsgProcessor: xor}
			dest, err := tcpServer.Start()
			common.Must(err)
			defer tcpServer.Close()

			userID := protocol.NewID(uuid.New())
			serverPort := tcp.PickPort()

			streamSettings := &internet.StreamConfig{
				Tcpmasks: []*serial.TypedMessage{serial.ToTypedMessage(c.mask)},
			}

			serverConfig := &core.Config{
				Inbound: []*core.InboundHandlerConfig{
					{
						ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
							PortList:       &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
							Listen:         net.NewIPOrDomain(net.LocalHostIP),
							StreamSettings: streamSettings,
						}),
						ProxySettings: serial.ToTypedMessage(&inbound.Config{
							User: []*protocol.User{
								{
									Account: serial.ToTypedMessage(&vmess.Account{Id: userID.String()}),
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
							Receiver: &protocol.ServerEndpoint{
								Address: net.NewIPOrDomain(net.LocalHostIP),
								Port:    uint32(serverPort),
								User: &protocol.User{
									Account: serial.ToTypedMessage(&vmess.Account{Id: userID.String()}),
								},
							},
						}),
						SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
							StreamSettings: streamSettings,
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
		})
	}
}
