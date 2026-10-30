package scenarios

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/grpc"
	"github.com/xtls/xray-core/transport/internet/websocket"
)

func TestSocksMuxConcurrentTCP(t *testing.T) {
	for _, transport := range []struct {
		name   string
		stream *internet.StreamConfig
	}{
		{name: "tcp"},
		{name: "websocket", stream: &internet.StreamConfig{
			ProtocolName:      "websocket",
			TransportSettings: []*internet.TransportConfig{{ProtocolName: "websocket", Settings: serial.ToTypedMessage(&websocket.Config{})}},
		}},
		{name: "grpc", stream: &internet.StreamConfig{
			ProtocolName:      "grpc",
			TransportSettings: []*internet.TransportConfig{{ProtocolName: "grpc", Settings: serial.ToTypedMessage(&grpc.Config{ServiceName: "mux"})}},
		}},
		{name: "grpc-multi", stream: &internet.StreamConfig{
			ProtocolName:      "grpc",
			TransportSettings: []*internet.TransportConfig{{ProtocolName: "grpc", Settings: serial.ToTypedMessage(&grpc.Config{ServiceName: "mux", MultiMode: true})}},
		}},
	} {
		t.Run(transport.name, func(t *testing.T) {
			target := &tcp.Server{MsgProcessor: xor}
			dest, err := target.Start()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = target.Close() })
			serverPort, clientPort := tcp.PickPort(), tcp.PickPort()
			serverConfig := &core.Config{
				Inbound: []*core.InboundHandlerConfig{{
					ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
						PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
						Listen:   net.NewIPOrDomain(net.LocalHostIP), StreamSettings: transport.stream,
					}),
					ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{}),
				}},
				Outbound: []*core.OutboundHandlerConfig{{ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				})}},
			}
			clientConfig := &core.Config{
				Inbound: []*core.InboundHandlerConfig{{
					ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
						PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
						Listen:   net.NewIPOrDomain(net.LocalHostIP),
					}),
					ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
						RewriteAddress: net.NewIPOrDomain(dest.Address), RewritePort: uint32(dest.Port),
						AllowedNetworks: []net.Network{net.Network_TCP},
					}),
				}},
				Outbound: []*core.OutboundHandlerConfig{{
					SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
						StreamSettings:    transport.stream,
						MultiplexSettings: &proxyman.MultiplexingConfig{Enabled: true, Concurrency: 8},
					}),
					ProxySettings: serial.ToTypedMessage(&socks.ClientConfig{Server: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP), Port: uint32(serverPort),
					}}),
				}},
			}
			for _, config := range []*core.Config{serverConfig, clientConfig} {
				instance, err := core.New(withDefaultApps(config))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = instance.Close() })
				if err := instance.Start(); err != nil {
					t.Fatal(err)
				}
			}
			start := make(chan struct{})
			results := make(chan error, 8)
			var connections []net.Conn
			for range 8 {
				conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", clientPort.String()))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = conn.Close() })
				if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
					t.Fatal(err)
				}
				connections = append(connections, conn)
			}
			var wg sync.WaitGroup
			for id, conn := range connections {
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer conn.Close()
					<-start
					payload := bytes.Repeat([]byte{byte(id)}, 32*1024)
					response := make([]byte, len(payload))
					for round := 0; round < 4; round++ {
						if _, err := io.Copy(conn, bytes.NewReader(payload)); err != nil {
							results <- err
							return
						}
						if _, err := io.ReadFull(conn, response); err != nil {
							results <- err
							return
						}
						if !bytes.Equal(response, xor(payload)) {
							results <- fmt.Errorf("corrupted response for session %d", id)
							return
						}
					}
				}()
			}
			close(start)
			wg.Wait()
			close(results)
			for err := range results {
				t.Error(err)
			}
		})
	}
}
