package socks

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"
)

func TestNewServerSocketSettings(t *testing.T) {
	settings := &internet.SocketConfig{Interface: "test-interface"}
	for _, test := range []struct {
		name   string
		stream any
		want   *internet.SocketConfig
	}{
		{name: "absent stream"},
		{name: "nil stream", stream: (*internet.MemoryStreamConfig)(nil)},
		{name: "empty stream", stream: &internet.MemoryStreamConfig{}},
		{name: "configured", stream: &internet.MemoryStreamConfig{SocketSettings: settings}, want: settings},
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
			if object.(*Server).socketSettings != test.want {
				t.Fatal("inbound socket settings were not retained for UDP association")
			}
		})
	}
}
