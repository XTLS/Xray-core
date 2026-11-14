package scenarios

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
)

func TestVMessDynamicUserRoute(t *testing.T) {
	start := func(t *testing.T, input string) {
		t.Helper()
		var config conf.Config
		if err := json.Unmarshal([]byte(input), &config); err != nil {
			t.Fatal(err)
		}
		built, err := config.Build()
		if err != nil {
			t.Fatal(err)
		}
		instance, err := core.New(built)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { instance.Close() })
		if err := instance.Start(); err != nil {
			t.Fatal(err)
		}
	}
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			var ports [2]net.Port
			for i := range ports {
				processor := func(msg []byte) []byte { return bytes.Repeat([]byte{byte('A' + i)}, len(msg)) }
				if network == "tcp" {
					target := &tcp.Server{MsgProcessor: processor}
					dest, err := target.Start()
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { target.Close() })
					ports[i] = dest.Port
				} else {
					target := &udp.Server{MsgProcessor: processor}
					dest, err := target.Start()
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { target.Close() })
					ports[i] = dest.Port
				}
			}
			serverPort := tcp.PickPort()
			// One server and one registered identity remain unchanged for every client below.
			start(t, fmt.Sprintf(`{
				"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"vmess","settings":{"clients":[{"id":"317530a8-3c1d-1234-8d8e-7cb70aedf158","userRoute":true}]}}],
				"outbounds":[{"tag":"block","protocol":"blackhole"},
					{"tag":"A","protocol":"freedom","settings":{"redirect":"127.0.0.1:%d","finalRules":[{"action":"allow"}]}},
					{"tag":"B","protocol":"freedom","settings":{"redirect":"127.0.0.1:%d","finalRules":[{"action":"allow"}]}}],
				"routing":{"rules":[{"userRoute":0,"outboundTag":"A"},{"userRoute":65535,"outboundTag":"B"}]}
			}`, serverPort, ports[0], ports[1]))
			for _, security := range []string{"aes-128-gcm", "chacha20-poly1305"} {
				for _, mux := range []bool{false, true} {
					for index, route := range []int{0, 65535} {
						t.Run(fmt.Sprintf("%s/mux=%t/route=%d", security, mux, route), func(t *testing.T) {
							clientPort := tcp.PickPort()
							if network == "udp" {
								clientPort = udp.PickPort()
							}
							start(t, fmt.Sprintf(`{
								"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1","port":1,"network":%q}}],
								"outbounds":[{"protocol":"vmess","settings":{"address":"127.0.0.1","port":%d,"id":"317530a8-3c1d-%04x-8d8e-7cb70aedf158","userRoute":true,"security":%q},"mux":{"enabled":%t,"concurrency":4}}]
							}`, clientPort, network, serverPort, route, security, mux))
							conn, err := net.Dial(network, fmt.Sprintf("127.0.0.1:%d", clientPort))
							if err != nil {
								t.Fatal(err)
							}
							defer conn.Close()
							conn.SetDeadline(time.Now().Add(5 * time.Second))
							if _, err := conn.Write([]byte("route")); err != nil {
								t.Fatal(err)
							}
							reply := make([]byte, 5)
							if _, err := io.ReadFull(conn, reply); err != nil {
								t.Fatal(err)
							}
							if want := bytes.Repeat([]byte{byte('A' + index)}, 5); !bytes.Equal(reply, want) {
								t.Fatalf("wrong outbound: got %q, want %q", reply, want)
							}
						})
					}
				}
			}
		})
	}
}
