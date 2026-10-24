package scenarios

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/commander"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type vlessRemoveUserCase struct {
	name    string
	mux     bool
	reality bool
}

// RemoveUser must also close the user's live connections, or a disabled user keeps relaying until idle timeout.
func TestVlessRemoveUserClosesLiveConnections(t *testing.T) {
	cases := []vlessRemoveUserCase{
		{name: "raw"},
		{name: "mux", mux: true},
		{name: "vision-reality", reality: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			testVlessRemoveUserClosesLiveConnections(t, tc)
		})
	}
}

func testVlessRemoveUserClosesLiveConnections(t *testing.T, tc vlessRemoveUserCase) {
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	alice := vlessTestAccount(protocol.NewID(uuid.New()).String(), tc.reality)
	bob := vlessTestAccount(protocol.NewID(uuid.New()).String(), tc.reality)

	cmdPort := tcp.PickPort()
	serverPort := tcp.PickPort()
	alicePort := tcp.PickPort()
	bobPort := tcp.PickPort()

	privateKey, _ := base64.RawURLEncoding.DecodeString("aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks")
	publicKey, _ := base64.RawURLEncoding.DecodeString("E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM")
	shortID := make([]byte, 8)
	hex.Decode(shortID, []byte("0123456789abcdef"))

	serverReceiver := &proxyman.ReceiverConfig{
		PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
		Listen:   net.NewIPOrDomain(net.LocalHostIP),
	}
	clientSender := &proxyman.SenderConfig{}
	if tc.mux {
		clientSender.MultiplexSettings = &proxyman.MultiplexingConfig{Enabled: true, Concurrency: 4}
	}
	if tc.reality {
		serverReceiver.StreamSettings = &internet.StreamConfig{
			ProtocolName: "tcp",
			SecurityType: serial.GetMessageType(&reality.Config{}),
			SecuritySettings: []*serial.TypedMessage{
				serial.ToTypedMessage(&reality.Config{
					Show:        true,
					Dest:        "www.google.com:443",
					ServerNames: []string{"www.google.com"},
					PrivateKey:  privateKey,
					ShortIds:    [][]byte{shortID},
					Type:        "tcp",
				}),
			},
		}
		clientSender.StreamSettings = &internet.StreamConfig{
			ProtocolName: "tcp",
			TransportSettings: []*internet.TransportConfig{
				{ProtocolName: "tcp", Settings: serial.ToTypedMessage(&transtcp.Config{})},
			},
			SecurityType: serial.GetMessageType(&reality.Config{}),
			SecuritySettings: []*serial.TypedMessage{
				serial.ToTypedMessage(&reality.Config{
					Show:        true,
					Fingerprint: "chrome",
					ServerName:  "www.google.com",
					PublicKey:   publicKey,
					ShortId:     shortID,
					SpiderX:     "/",
				}),
			},
		}
	}

	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&commander.Config{
				Tag:     "api",
				Service: []*serial.TypedMessage{serial.ToTypedMessage(&command.Config{})},
			}),
			serial.ToTypedMessage(&router.Config{
				Rule: []*router.RoutingRule{
					{InboundTag: []string{"api"}, TargetTag: &router.RoutingRule_Tag{Tag: "api"}},
				},
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				Tag:              "v",
				ReceiverSettings: serial.ToTypedMessage(serverReceiver),
				ProxySettings: serial.ToTypedMessage(&inbound.Config{
					Users: []*protocol.User{
						{Email: "alice@test", Account: serial.ToTypedMessage(alice)},
						{Email: "bob@test", Account: serial.ToTypedMessage(bob)},
					},
				}),
			},
			{
				Tag: "api",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(cmdPort)}},
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
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
			},
		},
	}

	clientInbound := func(tag string, port net.Port) *core.InboundHandlerConfig {
		return &core.InboundHandlerConfig{
			Tag: tag,
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(port)}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
				RewriteAddress:  net.NewIPOrDomain(dest.Address),
				RewritePort:     uint32(dest.Port),
				AllowedNetworks: []net.Network{net.Network_TCP},
			}),
		}
	}
	clientOutbound := func(tag string, account *vless.Account) *core.OutboundHandlerConfig {
		return &core.OutboundHandlerConfig{
			Tag:            tag,
			SenderSettings: serial.ToTypedMessage(clientSender),
			ProxySettings: serial.ToTypedMessage(&outbound.Config{
				Vnext: &protocol.ServerEndpoint{
					Address: net.NewIPOrDomain(net.LocalHostIP),
					Port:    uint32(serverPort),
					User:    &protocol.User{Account: serial.ToTypedMessage(account)},
				},
			}),
		}
	}
	clientConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&router.Config{
				Rule: []*router.RoutingRule{
					{InboundTag: []string{"in-alice"}, TargetTag: &router.RoutingRule_Tag{Tag: "out-alice"}},
					{InboundTag: []string{"in-bob"}, TargetTag: &router.RoutingRule_Tag{Tag: "out-bob"}},
				},
			}),
		},
		Inbound:  []*core.InboundHandlerConfig{clientInbound("in-alice", alicePort), clientInbound("in-bob", bobPort)},
		Outbound: []*core.OutboundHandlerConfig{clientOutbound("out-alice", alice), clientOutbound("out-bob", bob)},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	aliceConn := dialLocal(t, alicePort)
	defer aliceConn.Close()
	bobConn := dialLocal(t, bobPort)
	defer bobConn.Close()
	if err := testTCPConn2(aliceConn, 1024, 10*time.Second)(); err != nil {
		t.Fatal("alice before removal: ", err)
	}
	if err := testTCPConn2(bobConn, 1024, 10*time.Second)(); err != nil {
		t.Fatal("bob before removal: ", err)
	}

	cmdConn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", cmdPort), grpc.WithTransportCredentials(insecure.NewCredentials()))
	common.Must(err)
	defer cmdConn.Close()
	hsClient := command.NewHandlerServiceClient(cmdConn)
	if _, err := hsClient.AlterInbound(context.Background(), &command.AlterInboundRequest{
		Tag:       "v",
		Operation: serial.ToTypedMessage(&command.RemoveUserOperation{Email: "alice@test"}),
	}); err != nil {
		t.Fatal("remove alice: ", err)
	}

	if err := expectClosedByPeer(aliceConn, 5*time.Second); err != nil {
		t.Error("alice's live connection after RemoveUser: ", err)
	}
	if err := testTCPConn2(bobConn, 1024, 10*time.Second)(); err != nil {
		t.Error("bob's connection must survive alice's removal: ", err)
	}

	if _, err := hsClient.AlterInbound(context.Background(), &command.AlterInboundRequest{
		Tag: "v",
		Operation: serial.ToTypedMessage(&command.AddUserOperation{
			User: &protocol.User{Email: "alice@test", Account: serial.ToTypedMessage(alice)},
		}),
	}); err != nil {
		t.Fatal("re-add alice: ", err)
	}
	if err := testTCPConn(alicePort, 1024, 10*time.Second)(); err != nil {
		t.Error("alice after re-add: ", err)
	}
}

func vlessTestAccount(id string, vision bool) *vless.Account {
	account := &vless.Account{Id: id}
	if vision {
		account.Flow = vless.XRV
	}
	return account
}

func dialLocal(t *testing.T, port net.Port) net.Conn {
	t.Helper()
	conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: []byte{127, 0, 0, 1}, Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func expectClosedByPeer(conn net.Conn, timeout time.Duration) error {
	conn.SetReadDeadline(time.Now().Add(timeout))
	_, err := conn.Read(make([]byte, 1))
	if errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) {
		return nil
	}
	return fmt.Errorf("expected the server to close it, got: %v", err)
}
