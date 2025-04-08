package scenarios

import (
	"testing"
	//"time"

	"github.com/hosemorinho412/xray-core/app/log"
	"github.com/hosemorinho412/xray-core/app/proxyman"
	"github.com/hosemorinho412/xray-core/common"
	clog "github.com/hosemorinho412/xray-core/common/log"
	"github.com/hosemorinho412/xray-core/common/net"
	"github.com/hosemorinho412/xray-core/common/serial"
	core "github.com/hosemorinho412/xray-core/core"
	"github.com/hosemorinho412/xray-core/infra/conf"
	"github.com/hosemorinho412/xray-core/proxy/dokodemo"
	"github.com/hosemorinho412/xray-core/proxy/freedom"
	"github.com/hosemorinho412/xray-core/proxy/wireguard"
	"github.com/hosemorinho412/xray-core/testing/servers/tcp"
	"github.com/hosemorinho412/xray-core/testing/servers/udp"
	//"golang.org/x/sync/errgroup"
)

func TestWireguard(t *testing.T) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverPrivate, _ := conf.ParseWireGuardKey("EGs4lTSJPmgELx6YiJAmPR2meWi6bY+e9rTdCipSj10=")
	serverPublic, _ := conf.ParseWireGuardKey("osAMIyil18HeZXGGBDC9KpZoM+L2iGyXWVSYivuM9B0=")
	clientPrivate, _ := conf.ParseWireGuardKey("CPQSpgxgdQRZa5SUbT3HLv+mmDVHLW5YR/rQlzum/2I=")
	clientPublic, _ := conf.ParseWireGuardKey("MmLJ5iHFVVBp7VsB0hxfpQ0wEzAbT2KQnpQpj0+RtBw=")

	serverPort := udp.PickPort()
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
				ProxySettings: serial.ToTypedMessage(&wireguard.DeviceConfig{
					IsClient:    false,
					NoKernelTun: false,
					Endpoint:    []string{"10.0.0.1"},
					Mtu:         1420,
					SecretKey:   serverPrivate,
					Peers: []*wireguard.PeerConfig{{
						PublicKey:  serverPublic,
						AllowedIps: []string{"0.0.0.0/0", "::0/0"},
					}},
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
				ProxySettings: serial.ToTypedMessage(&wireguard.DeviceConfig{
					IsClient:    true,
					NoKernelTun: false,
					Endpoint:    []string{"10.0.0.2"},
					Mtu:         1420,
					SecretKey:   clientPrivate,
					Peers: []*wireguard.PeerConfig{{
						Endpoint:   "127.0.0.1:" + serverPort.String(),
						PublicKey:  clientPublic,
						AllowedIps: []string{"0.0.0.0/0", "::0/0"},
					}},
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	// FIXME: for some reason wg server does not receive

	// var errg errgroup.Group
	// for i := 0; i < 1; i++ {
	// 	errg.Go(testTCPConn(clientPort, 1024, time.Second*2))
	// }
	// if err := errg.Wait(); err != nil {
	// 	t.Error(err)
	// }
}
