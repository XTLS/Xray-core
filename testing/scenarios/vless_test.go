package scenarios

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	transtcp "github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/sync/errgroup"
)

func TestVless(t *testing.T) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	userID := protocol.NewID(uuid.New())
	serverPort := tcp.PickPort()
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
				ProxySettings: serial.ToTypedMessage(&inbound.Config{
					Clients: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vless.Account{
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
				ProxySettings: serial.ToTypedMessage(&outbound.Config{
					Vnext: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(serverPort),
						User:    &protocol.User{
							Account: serial.ToTypedMessage(&vless.Account{
								Id: userID.String(),
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

	var errg errgroup.Group
	for range 3 {
		errg.Go(testTCPConn(clientPort, 1024*1024, time.Second*30))
	}
	if err := errg.Wait(); err != nil {
		t.Error(err)
	}
}

func TestVlessMuxTcp(t *testing.T) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	userID := protocol.NewID(uuid.New())
	serverPort := tcp.PickPort()
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
				ProxySettings: serial.ToTypedMessage(&inbound.Config{
					Clients: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vless.Account{
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
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					MultiplexSettings: &proxyman.MultiplexingConfig{
						Enabled:     true,
						Concurrency: 4,
					},
				}),
				ProxySettings: serial.ToTypedMessage(&outbound.Config{
					Vnext: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(serverPort),
						User:    &protocol.User{
							Account: serial.ToTypedMessage(&vless.Account{
								Id: userID.String(),
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

	for range "abcd" {
		var errg errgroup.Group
		for range 3 {
			errg.Go(testTCPConn(clientPort, 10240, time.Second*20))
		}
		if err := errg.Wait(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
	}
}

func TestVlessEncMuxTcp(t *testing.T) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	userID := protocol.NewID(uuid.New())
	serverPort := tcp.PickPort()
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
				ProxySettings: serial.ToTypedMessage(&inbound.Config{
					Clients: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vless.Account{
								Id: userID.String(),
							}),
						},
					},
					SecondsFrom: 600, //mlkem768x25519plus.native.600s.
					Decryption: "Gzh5Aa3Ibo3343XFC7V2a8ucOpFeGjOL6jMlBZAfjqyty2rdRms8xccBAm68imYw2q96gg2dcueeL2r7n_2YzQ",
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
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					MultiplexSettings: &proxyman.MultiplexingConfig{
						Enabled:     true,
						Concurrency: 4,
					},
				}),
				ProxySettings: serial.ToTypedMessage(&outbound.Config{
					Vnext: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(serverPort),
						User:    &protocol.User{
							Account: serial.ToTypedMessage(&vless.Account{
								Id: userID.String(),
								Seconds: 1, //mlkem768x25519plus.native.0rtt.
								Encryption: "ExaMB4tIHpFikMeZwAJ8_8hxpZNi3gY13Ft455yC04xiCWgWUwMvKUwDQVm8zLcE8EKnjVlhRDmkTzMzvTMZyYlswCuqx0YK9kVNNFcrQJWD8JpAmTN8fffApIoWitDEAUTEp9S_Ehxo-9a2evRyKqJcQ6WmPiiyGbZrnNAfLKhdRsA15rZt6eKMVQExtDpucfaFc2E4-GtKzKd7P0I6bXccC1q4gqyZcXiEfOmmWBTPMTkNPEUdnQVsPiSWgJxslQZ5pYlPE7GQE7qoxYBItDMhkHZ4l0YwsvgZ1EQ2yTEn9DOxbyMihLk4kSAtg1IrW7tCTNkhyVsUY3SeyReB2sfN2AU-TXmVGUJMTKJ1jfywu8JIb9lG14HB1Rku6nVNcIMTzyshvsi_8AQFCSOcDdQ7ZpBxKxW7N1tKXBI0shq7vWdufjpYCjAVh-k_QgonVOwadYt-wPMxDntbWzEf_yC9eFQ6cBGd5smWNeSQZwAvqXw_WVPD56EVlaQ5HpsOkqBdy1Enr1NnH7WdgNsfk6RSQhRgW1dF9XBUKylpqsvOXkq3I0fLuuJFfuEZu4MeNvdgI2mbM_UxK8AzlRwkm7Eb1WQfm-S05HJefdZzu8kHYamggwtNQum_NtODzRgw3uWbjYbEBIY0j9IMhyGynOYQHHmrR2kT-dh08GwVD7BfsJRvFYgy2ZI8a3xGgHyi6MKKE8g7krEd-ne_4ddSaysgctaiiLwI4NVRbYJIT8XEbmKTIwoZx4R7m7AffYJo2NlfEPREg8stBcY5dAGXeSwD0pxs-jCJOeifQYq7Elq216SrwCmayLg3XJcpxutOmkhai6hRO6eBP6uy9XlLXyMt3TW6isx_rRt1hXCezkl_8hPEcqI9tPE0ZYVQ-eMh2_e35gQyPUw02aequ4ojaHV03QaSMquqF8RXG7k1gDed9vqex3aFaSN6UUNkebLKrqAiPmq0fccQ3qdbAxLGZ0ZFF5mIwEiFoTM6V4yPgntkRYtxcCKK-5YkPfsIunrM3EsWDCovp_Ahdfs-aqQLqzk1wVKTLQaQI5ApBlmGB3EauNdHFJBoeGZOF9e7QbGujhGRGMpS1fFtI2SqlcXINZU7YvR2JMfBrvBYZ9whXawM_Rg31IJR1raMGAEm6hNpa7SBD0cprIZxG6HKUQFMGHVlVohjwpWE5AGIc5Rc8Va2x8e3zFTMTUIwCdMz1XlNaqBMldJx01JQLwgSsnfGGlEJ_jYujvYNo0EBk4yev1Ap6nO-zSU-WtimlhEP0-cb22Q6e4wCEnWfO-lABJsrhwhrbloM51k5QVIefNyIvDWBszpRsreidUZVU4TOH2EoltYslWdPkcckfCplFLyvGKBItoAPRTOKRCjOsqlmj9OvpbDCzedZUmjLNfoLSwsPC7Nk2FpIkVUG6WxCE2YiU9LFrZIgWRKwUluM_at9w7wowRkujXEAQiJKtuUWQCxGyVbJtufLmQI6_yafmwgLoSlyE0cL-_Rf4nBCBjJnmyBDRvAoA-W08vw53uMt3RnFVwKFqo3PonmYAETv5rrMjh3L3K16QS-2EgL_R7WAFd0",
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

	for range "abcd" {
		var errg errgroup.Group
		for range 3 {
			errg.Go(testTCPConn(clientPort, 10240, time.Second*20))
		}
		if err := errg.Wait(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
	}
}

func TestVlessTls(t *testing.T) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	userID := protocol.NewID(uuid.New())
	serverPort := tcp.PickPort()
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
					StreamSettings: &internet.StreamConfig{
						ProtocolName: "tcp",
						SecurityType: serial.GetMessageType(&tls.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&tls.Config{
								Certificate: []*tls.Certificate{tls.ParseCertificate(cert.MustGenerate(nil))},
							}),
						},
					},
				}),
				ProxySettings: serial.ToTypedMessage(&inbound.Config{
					Clients: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vless.Account{
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
				ProxySettings: serial.ToTypedMessage(&outbound.Config{
					Vnext: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(serverPort),
						User:    &protocol.User{
							Account: serial.ToTypedMessage(&vless.Account{
								Id: userID.String(),
							}),
						},
					},
				}),
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: &internet.StreamConfig{
						ProtocolName: "tcp",
						TransportSettings: []*internet.TransportConfig{
							{
								ProtocolName: "tcp",
								Settings:     serial.ToTypedMessage(&transtcp.Config{}),
							},
						},
						SecurityType: serial.GetMessageType(&tls.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&tls.Config{
								AllowInsecure: true,
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

	var errg errgroup.Group
	for range 3 {
		errg.Go(testTCPConn(clientPort, 1024*1024, time.Second*30))
	}
	if err := errg.Wait(); err != nil {
		t.Error(err)
	}
}

func TestVlessXtlsVision(t *testing.T) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	userID := protocol.NewID(uuid.New())
	serverPort := tcp.PickPort()
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
					StreamSettings: &internet.StreamConfig{
						ProtocolName: "tcp",
						SecurityType: serial.GetMessageType(&tls.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&tls.Config{
								Certificate: []*tls.Certificate{tls.ParseCertificate(cert.MustGenerate(nil))},
							}),
						},
					},
				}),
				ProxySettings: serial.ToTypedMessage(&inbound.Config{
					Clients: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vless.Account{
								Id:   userID.String(),
								Flow: vless.XRV,
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
				ProxySettings: serial.ToTypedMessage(&outbound.Config{
					Vnext: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(serverPort),
						User:    &protocol.User{
							Account: serial.ToTypedMessage(&vless.Account{
								Id:   userID.String(),
								Flow: vless.XRV,
							}),
						},
					},
				}),
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: &internet.StreamConfig{
						ProtocolName: "tcp",
						TransportSettings: []*internet.TransportConfig{
							{
								ProtocolName: "tcp",
								Settings:     serial.ToTypedMessage(&transtcp.Config{}),
							},
						},
						SecurityType: serial.GetMessageType(&tls.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&tls.Config{
								AllowInsecure: true,
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

	var errg errgroup.Group
	for range 3 {
		errg.Go(testTCPConn(clientPort, 1024*1024, time.Second*30))
	}
	if err := errg.Wait(); err != nil {
		t.Error(err)
	}
}

func TestVlessXtlsVisionReality(t *testing.T) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	userID := protocol.NewID(uuid.New())
	serverPort := tcp.PickPort()
	privateKey, _ := base64.RawURLEncoding.DecodeString("aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks")
	publicKey, _ := base64.RawURLEncoding.DecodeString("E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM")
	shortIds := make([][]byte, 1)
	shortIds[0] = make([]byte, 8)
	hex.Decode(shortIds[0], []byte("0123456789abcdef"))
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
					StreamSettings: &internet.StreamConfig{
						ProtocolName: "tcp",
						SecurityType: serial.GetMessageType(&reality.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&reality.Config{
								Show:        true,
								Dest:        "www.google.com:443", // use google for now, may fail in some region
								ServerNames: []string{"www.google.com"},
								PrivateKey:  privateKey,
								ShortIds:    shortIds,
								Type:        "tcp",
							}),
						},
					},
				}),
				ProxySettings: serial.ToTypedMessage(&inbound.Config{
					Clients: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vless.Account{
								Id:   userID.String(),
								Flow: vless.XRV,
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
				ProxySettings: serial.ToTypedMessage(&outbound.Config{
					Vnext: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(serverPort),
						User:    &protocol.User{
							Account: serial.ToTypedMessage(&vless.Account{
								Id:   userID.String(),
								Flow: vless.XRV,
							}),
						},
					},
				}),
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: &internet.StreamConfig{
						ProtocolName: "tcp",
						TransportSettings: []*internet.TransportConfig{
							{
								ProtocolName: "tcp",
								Settings:     serial.ToTypedMessage(&transtcp.Config{}),
							},
						},
						SecurityType: serial.GetMessageType(&reality.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&reality.Config{
								Show:        true,
								Fingerprint: "chrome",
								ServerName:  "www.google.com",
								PublicKey:   publicKey,
								ShortId:     shortIds[0],
								SpiderX:     "/",
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

	var errg errgroup.Group
	for range 3 {
		errg.Go(testTCPConn(clientPort, 1024*1024, time.Second*30))
	}
	if err := errg.Wait(); err != nil {
		t.Error(err)
	}
}
