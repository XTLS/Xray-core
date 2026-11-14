package scenarios

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/wireguard"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/sync/errgroup"
)

func wireguardPublicKey(private string) string {
	key, err := wireguard.ParseKey(private)
	common.Must(err)
	var public [32]byte
	curve25519.ScalarBaseMult(&public, key)
	return hex.EncodeToString(public[:])
}

func TestWireguard(t *testing.T) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	udpServer := udp.Server{
		MsgProcessor: xor,
	}
	udpDest, err := udpServer.Start()
	common.Must(err)
	defer udpServer.Close()

	serverPrivate, _ := conf.ParseWireGuardKey("EGs4lTSJPmgELx6YiJAmPR2meWi6bY+e9rTdCipSj10=")
	clientPrivate, _ := conf.ParseWireGuardKey("CPQSpgxgdQRZa5SUbT3HLv+mmDVHLW5YR/rQlzum/2I=")

	// What the client asks for is somewhere else, the stack of the server takes nothing that is for this machine.
	redirect := func(tag string, dest net.Destination) *core.OutboundHandlerConfig {
		return &core.OutboundHandlerConfig{
			Tag: tag,
			ProxySettings: serial.ToTypedMessage(&freedom.Config{
				DestinationOverride: &freedom.DestinationOverride{
					Server: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(dest.Address),
						Port:    uint32(dest.Port),
					},
				},
				FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
			}),
		}
	}
	serverPort := udp.PickPort()
	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Warning,
				ErrorLogType:  log.LogType_Console,
			}),
			serial.ToTypedMessage(&router.Config{
				Rule: []*router.RoutingRule{
					{Networks: []net.Network{net.Network_TCP}, TargetTag: &router.RoutingRule_Tag{Tag: "tcp"}},
					{Networks: []net.Network{net.Network_UDP}, TargetTag: &router.RoutingRule_Tag{Tag: "udp"}},
				},
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&wireguard.DeviceConfig{
					IsClient:  false,
					Endpoint:  []string{"10.0.0.1", "fd00::1"},
					Mtu:       1420,
					SecretKey: serverPrivate,
					Users: []*protocol.User{{
						Email: "love@xray.com",
						Account: serial.ToTypedMessage(&wireguard.PeerConfig{
							PublicKey:  wireguardPublicKey(clientPrivate),
							AllowedIps: []string{"10.0.0.2/32", "fd00::2/128"},
						}),
					}},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			redirect("tcp", dest),
			redirect("udp", udpDest),
		},
	}

	clientPort := tcp.PickPort()
	client6Port := tcp.PickPort()
	clientUDPPort := udp.PickPort()
	dokodemoInbound := func(port net.Port, dest net.Destination) *core.InboundHandlerConfig {
		return &core.InboundHandlerConfig{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(port)}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
				RewriteAddress:  net.NewIPOrDomain(dest.Address),
				RewritePort:     uint32(dest.Port),
				AllowedNetworks: []net.Network{dest.Network},
			}),
		}
	}
	clientConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Warning,
				ErrorLogType:  log.LogType_Console,
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			dokodemoInbound(clientPort, net.TCPDestination(net.ParseAddress("192.0.2.1"), 7)),
			dokodemoInbound(client6Port, net.TCPDestination(net.ParseAddress("2001:db8::1"), 7)),
			dokodemoInbound(clientUDPPort, net.UDPDestination(net.ParseAddress("192.0.2.1"), 7)),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&wireguard.DeviceConfig{
					IsClient:    true,
					NoKernelTun: true,
					Endpoint:    []string{"10.0.0.2", "fd00::2"},
					Mtu:         1420,
					SecretKey:   clientPrivate,
					Peers: []*wireguard.PeerConfig{{
						Endpoint:   "127.0.0.1:" + serverPort.String(),
						PublicKey:  wireguardPublicKey(serverPrivate),
						AllowedIps: []string{"0.0.0.0/0", "::0/0"},
					}},
				}),
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	var errg errgroup.Group
	for range 3 {
		errg.Go(testTCPConn(clientPort, 1024*1024, time.Second*20))
	}
	errg.Go(testTCPConn(client6Port, 1024*1024, time.Second*20))
	errg.Go(testUDPConn(clientUDPPort, 1024, time.Second*5))
	if err := errg.Wait(); err != nil {
		t.Error(err)
	}
}
