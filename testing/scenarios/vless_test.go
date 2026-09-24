package scenarios

import (
	gotls "crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"sync"
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
					Users: []*protocol.User{
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
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
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
					RewriteAddress:  net.NewIPOrDomain(dest.Address),
					RewritePort:     uint32(dest.Port),
					AllowedNetworks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&outbound.Config{
					Vnext: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(serverPort),
						User: &protocol.User{
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

func TestVlessTls(t *testing.T) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))

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
								Certificate: []*tls.Certificate{tls.ParseCertificate(ct)},
							}),
						},
					},
				}),
				ProxySettings: serial.ToTypedMessage(&inbound.Config{
					Users: []*protocol.User{
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
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
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
					RewriteAddress:  net.NewIPOrDomain(dest.Address),
					RewritePort:     uint32(dest.Port),
					AllowedNetworks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&outbound.Config{
					Vnext: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(serverPort),
						User: &protocol.User{
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
								PinnedPeerCertSha256: [][]byte{ctHash[:]},
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

	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))

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
								Certificate: []*tls.Certificate{tls.ParseCertificate(ct)},
							}),
						},
					},
				}),
				ProxySettings: serial.ToTypedMessage(&inbound.Config{
					Users: []*protocol.User{
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
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
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
					RewriteAddress:  net.NewIPOrDomain(dest.Address),
					RewritePort:     uint32(dest.Port),
					AllowedNetworks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&outbound.Config{
					Vnext: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(serverPort),
						User: &protocol.User{
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
								PinnedPeerCertSha256: [][]byte{ctHash[:]},
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

// After Vision switches to direct copy, closing the proxy connection must not
// put an outer TLS record (close_notify) into the inner TLS stream.
func TestVlessXtlsVisionDirectCopyClose(t *testing.T) {
	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	destCert, err := gotls.X509KeyPair(ct.ToPEM())
	common.Must(err)
	listener, err := gotls.Listen("tcp", "127.0.0.1:0", &gotls.Config{Certificates: []gotls.Certificate{destCert}})
	common.Must(err)
	defer listener.Close()
	destPort := net.Port(listener.Addr().(*net.TCPAddr).Port)

	payload := make([]byte, 64*1024)
	uplinkErr := make(chan error, 1)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second * 30))
				mode := make([]byte, 1)
				if _, err := io.ReadFull(conn, mode); err != nil {
					return
				}
				if mode[0] == 'd' {
					conn.Write(payload)
				} else {
					conn.Write(mode) // let the client's Vision switch before the payload
					b, err := io.ReadAll(conn)
					if err == nil && len(b) != len(payload) {
						err = errors.New("uplink: short read")
					}
					uplinkErr <- err
				}
				// Close without close_notify, like many real servers do.
				conn.(*gotls.Conn).NetConn().Close()
			}()
		}
	}()

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
								Certificate: []*tls.Certificate{tls.ParseCertificate(ct)},
							}),
						},
					},
				}),
				ProxySettings: serial.ToTypedMessage(&inbound.Config{
					Users: []*protocol.User{
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
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
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
					RewriteAddress:  net.NewIPOrDomain(net.LocalHostIP),
					RewritePort:     uint32(destPort),
					AllowedNetworks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&outbound.Config{
					Vnext: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(serverPort),
						User: &protocol.User{
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
						SecurityType: serial.GetMessageType(&tls.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&tls.Config{
								PinnedPeerCertSha256: [][]byte{ctHash[:]},
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

	dial := func(mode byte) *gotls.Conn {
		conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: []byte{127, 0, 0, 1}, Port: int(clientPort)})
		common.Must(err)
		tlsConn := gotls.Client(conn, &gotls.Config{InsecureSkipVerify: true})
		tlsConn.SetDeadline(time.Now().Add(time.Second * 30))
		_, err = tlsConn.Write([]byte{mode})
		common.Must(err)
		return tlsConn
	}

	// downlink: the server side closes after the destination does
	conn := dial('d')
	b, err := io.ReadAll(conn)
	conn.Close()
	if err != nil {
		t.Error("downlink: ", err)
	} else if len(b) != len(payload) {
		t.Error("downlink: short read ", len(b))
	}

	// uplink: the client side closes after the application does
	conn = dial('u')
	_, err = io.ReadFull(conn, make([]byte, 1))
	common.Must(err)
	_, err = conn.Write(payload)
	common.Must(err)
	conn.NetConn().Close()
	if err := <-uplinkErr; err != nil {
		t.Error("uplink: ", err)
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
					Users: []*protocol.User{
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
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
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
					RewriteAddress:  net.NewIPOrDomain(dest.Address),
					RewritePort:     uint32(dest.Port),
					AllowedNetworks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&outbound.Config{
					Vnext: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(serverPort),
						User: &protocol.User{
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

// This testing test all known utls fingerprint in tls.PresetFingerprints that support reality (expect unsafe and random*)
// Beacuse figerprint support may be broken after utls/reality update
// Known working fingerprint: chrome, firefox, safari
func TestVlessRealityFingerprints(t *testing.T) {
	TestFingerprint := func(fingerprint string) error {
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
					ErrorLogType: log.LogType_None,
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
									Show:        false,
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
						Users: []*protocol.User{
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
					ProxySettings: serial.ToTypedMessage(&freedom.Config{
						FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
					}),
				},
			},
		}

		clientPort := tcp.PickPort()
		clientConfig := &core.Config{
			App: []*serial.TypedMessage{
				serial.ToTypedMessage(&log.Config{
					ErrorLogType: log.LogType_None,
				}),
			},
			Inbound: []*core.InboundHandlerConfig{
				{
					ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
						PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
						Listen:   net.NewIPOrDomain(net.LocalHostIP),
					}),
					ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
						RewriteAddress:  net.NewIPOrDomain(dest.Address),
						RewritePort:     uint32(dest.Port),
						AllowedNetworks: []net.Network{net.Network_TCP},
					}),
				},
			},
			Outbound: []*core.OutboundHandlerConfig{
				{
					ProxySettings: serial.ToTypedMessage(&outbound.Config{
						Vnext: &protocol.ServerEndpoint{
							Address: net.NewIPOrDomain(net.LocalHostIP),
							Port:    uint32(serverPort),
							User: &protocol.User{
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
							SecurityType: serial.GetMessageType(&reality.Config{}),
							SecuritySettings: []*serial.TypedMessage{
								serial.ToTypedMessage(&reality.Config{
									Show:        false,
									Fingerprint: fingerprint,
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

		err = testTCPConn(clientPort, 1024*1024, time.Second*15)()
		if err != nil {
			return err
		}
		return nil
	}
	fingerPrints := []string{"chrome", "firefox", "safari"}
	wg := sync.WaitGroup{}
	wg.Add(len(fingerPrints))
	for _, fp := range fingerPrints {
		go func() {
			err := TestFingerprint(fp)
			if err != nil {
				t.Errorf("Fingerprint %s test failed: %v", fp, err)
			} else {
				t.Logf("Fingerprint %s test passed", fp)
			}
			wg.Done()
		}()
	}
	wg.Wait()
}
