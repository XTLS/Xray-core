package socks

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"
)

func TestNewServerUDPSocketSettings(t *testing.T) {
	udp := &internet.SocketConfig{V6Only: true}
	tcp := &internet.SocketConfig{TcpKeepAliveIdle: 30}
	for _, test := range []struct {
		name   string
		stream any
		want   *internet.SocketConfig
	}{
		{name: "absent stream"},
		{name: "nil stream", stream: (*internet.MemoryStreamConfig)(nil)},
		{name: "empty stream", stream: &internet.MemoryStreamConfig{}},
		{name: "legacy sockopt", stream: &internet.MemoryStreamConfig{SocketSettings: tcp}},
		{name: "UDP only", stream: &internet.MemoryStreamConfig{UDPSocketSettings: udp}, want: udp},
		{name: "separate TCP and UDP", stream: &internet.MemoryStreamConfig{SocketSettings: tcp, UDPSocketSettings: udp}, want: udp},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			if test.stream != nil {
				ctx = session.ContextWithStreamSettings(ctx, test.stream)
			}
			instance, err := core.NewWithContext(ctx, &core.Config{})
			if err != nil {
				t.Fatal(err)
			}
			defer instance.Close()
			object, err := core.CreateObject(instance, &ServerConfig{UdpEnabled: true})
			if err != nil {
				t.Fatal(err)
			}
			if object.(*Server).udpSocketSettings != test.want {
				t.Fatal("SOCKS must retain only the explicit UDP socket settings")
			}
		})
	}
}
