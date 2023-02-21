package scenarios

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/shadowtls"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/sync/errgroup"
)

func TestShadowTLSTcp(t *testing.T) {
	password := make([]byte, 32)
	rand.Read(password)
	testShadowTLSTcp(t, shadowaead_2022.List[0], base64.StdEncoding.EncodeToString(password))
}

func testShadowTLSTcp(t *testing.T, method string, password string) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverPort := tcp.PickPort()
	serverPort = 18462
	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Debug,
				ErrorLogType:  log.LogType_Console,
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&shadowtls.ServerConfig{
					Version: 3,
					Users:   []*shadowtls.User{{Password: password}},
					Handshake: &shadowtls.HandshakeConfig{
						Address: net.NewIPOrDomain(net.DomainAddress("google.com")),
						Port:    443,
					},
					Detour: "detour",
				}),
			},
			{
				Tag: "detour",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort + 1)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&shadowsocks_2022.ServerConfig{
					Method:  method,
					Key:     password,
					Network: []net.Network{net.Network_TCP},
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
	clientPort = 12434
	clientConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Debug,
				ErrorLogType:  log.LogType_Console,
			}),
		},
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
				ProxySettings: serial.ToTypedMessage(&shadowsocks_2022.ClientConfig{
					Address: net.NewIPOrDomain(net.LocalHostIP),
					Port:    uint32(serverPort),
					Method:  method,
					Key:     password,
				}),
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					ProxySettings: &internet.ProxyConfig{
						Tag: "detour",
					},
				}),
			},
			{
				Tag: "detour",
				ProxySettings: serial.ToTypedMessage(&shadowtls.ClientConfig{
					Address:  net.NewIPOrDomain(net.LocalHostIP),
					Port:     uint32(serverPort),
					Version:  3,
					Password: password,
				}),
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: &internet.StreamConfig{
						SecurityType: serial.GetMessageType(&tls.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&tls.Config{
								ServerName: "google.com",
							}),
						},
					},
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	var errGroup errgroup.Group
	for i := 0; i < 10; i++ {
		errGroup.Go(testTCPConn(clientPort, 10240*1024, time.Second*20))
	}

	if err := errGroup.Wait(); err != nil {
		t.Error(err)
	}
}
