package scenarios

import (
	"context"
	"fmt"
	"io"
	gonet "net"
	"sync/atomic"
	"testing"
	"time"

	appdispatcher "github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	featureoutbound "github.com/xtls/xray-core/features/outbound"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vmess"
	vmessinbound "github.com/xtls/xray-core/proxy/vmess/inbound"
	vmessoutbound "github.com/xtls/xray-core/proxy/vmess/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/exchange"
)

type nativeMuxChildGuard struct {
	featureoutbound.Handler
	stream featureoutbound.StreamHandler
	native atomic.Int32
	legacy atomic.Int32
}

func (g *nativeMuxChildGuard) Dispatch(_ context.Context, link *transport.Link) {
	g.legacy.Add(1)
	common.Interrupt(link.Reader)
	common.Interrupt(link.Writer)
}

func (g *nativeMuxChildGuard) DispatchStream(ctx context.Context, source exchange.Stream) error {
	g.native.Add(1)
	return g.stream.DispatchStream(ctx, source)
}

func TestE1VMessNativeMuxChildren(t *testing.T) {
	echo, err := gonet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	targetPort := echo.Addr().(*gonet.TCPAddr).Port
	serverPort := tcp.PickPort()
	clientPort := tcp.PickPort()
	id := protocol.NewID(uuid.New()).String()
	apps := func() []*serial.TypedMessage {
		return []*serial.TypedMessage{
			serial.ToTypedMessage(&appdispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		}
	}
	serverConfig := &core.Config{
		App: apps(),
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(net.Port(serverPort))}}, Listen: net.NewIPOrDomain(net.LocalHostIP)}),
			ProxySettings:    serial.ToTypedMessage(&vmessinbound.Config{User: []*protocol.User{{Account: serial.ToTypedMessage(&vmess.Account{Id: id})}}}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{Tag: "egress", ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}})}},
	}
	server, err := core.New(serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	manager := server.GetFeature(featureoutbound.ManagerType()).(featureoutbound.Manager)
	real := manager.GetHandler("egress")
	if real == nil {
		t.Fatal("server outbound missing")
	}
	stream, ok := real.(featureoutbound.StreamHandler)
	if !ok {
		t.Fatal("server outbound lacks stream handler")
	}
	guard := &nativeMuxChildGuard{Handler: real, stream: stream}
	if err := manager.RemoveHandler(context.Background(), "egress"); err != nil {
		t.Fatal(err)
	}
	if err := manager.AddHandler(context.Background(), guard); err != nil {
		t.Fatal(err)
	}
	clientConfig := &core.Config{
		App: apps(),
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(net.Port(clientPort))}}, Listen: net.NewIPOrDomain(net.LocalHostIP)}),
			ProxySettings:    serial.ToTypedMessage(&dokodemo.Config{RewriteAddress: net.NewIPOrDomain(net.LocalHostIP), RewritePort: uint32(targetPort), AllowedNetworks: []net.Network{net.Network_TCP}}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{MultiplexSettings: &proxyman.MultiplexingConfig{Enabled: true, Concurrency: 4}}),
			ProxySettings:  serial.ToTypedMessage(&vmessoutbound.Config{Receiver: &protocol.ServerEndpoint{Address: net.NewIPOrDomain(net.LocalHostIP), Port: uint32(serverPort), User: &protocol.User{Account: serial.ToTypedMessage(&vmess.Account{Id: id, SecuritySettings: &protocol.SecurityConfig{Type: protocol.SecurityType_AES128_GCM}})}}}),
		}},
	}
	client, err := core.New(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	dial := func() gonet.Conn {
		c, e := gonet.DialTimeout("tcp", gonet.JoinHostPort("127.0.0.1", fmt.Sprint(clientPort)), time.Second)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(10 * time.Second))
		return c
	}
	a, b := dial(), dial()
	defer a.Close()
	defer b.Close()
	check := func(c gonet.Conn, p []byte) {
		t.Helper()
		if _, e := c.Write(p); e != nil {
			t.Fatal(e)
		}
		q := make([]byte, len(p))
		if _, e := io.ReadFull(c, q); e != nil {
			t.Fatal(e)
		}
		if string(q) != string(p) {
			t.Fatalf("echo=%q want=%q", q, p)
		}
	}
	check(a, []byte("child-a"))
	check(b, []byte("child-b"))
	a.Close()
	check(b, []byte("sibling-still-open"))
	if guard.native.Load() < 2 || guard.legacy.Load() != 0 {
		t.Fatalf("native=%d legacy=%d", guard.native.Load(), guard.legacy.Load())
	}
}
