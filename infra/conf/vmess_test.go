package conf_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/inbound"
	"github.com/xtls/xray-core/proxy/vmess/outbound"
)

func TestVMessUserRouteConfig(t *testing.T) {
	const id = "317530a8-3c1d-1234-8d8e-7cb70aedf158"
	for _, enabled := range []bool{false, true} {
		for _, shape := range []string{"clients", "users", "flat", "vnext"} {
			t.Run(fmt.Sprintf("%s/%t", shape, enabled), func(t *testing.T) {
				user := fmt.Sprintf(`{"id":%q,"userRoute":%t}`, id, enabled)
				var memory *protocol.MemoryUser
				if shape == "clients" || shape == "users" {
					var config VMessInboundConfig
					if err := json.Unmarshal([]byte(fmt.Sprintf(`{%q:[%s]}`, shape, user)), &config); err != nil {
						t.Fatal(err)
					}
					built, err := config.Build()
					if err != nil {
						t.Fatal(err)
					}
					memory, err = built.(*inbound.Config).User[0].ToMemoryUser()
					if err != nil {
						t.Fatal(err)
					}
				} else {
					input := fmt.Sprintf(`{"address":"127.0.0.1","port":443,"id":%q,"userRoute":%t}`, id, enabled)
					if shape == "vnext" {
						input = fmt.Sprintf(`{"vnext":[{"address":"127.0.0.1","port":443,"users":[%s]}]}`, user)
					}
					var config VMessOutboundConfig
					if err := json.Unmarshal([]byte(input), &config); err != nil {
						t.Fatal(err)
					}
					built, err := config.Build()
					if err != nil {
						t.Fatal(err)
					}
					memory, err = built.(*outbound.Config).Receiver.User.ToMemoryUser()
					if err != nil {
						t.Fatal(err)
					}
				}
				account := memory.Account.(*vmess.MemoryAccount)
				if account.UserRoute != enabled || account.ID.String() != id {
					t.Fatal("account configuration not preserved")
				}
			})
		}
	}
}

func TestVMessOutbound(t *testing.T) {
	creator := func() Buildable {
		return new(VMessOutboundConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"vnext": [{
					"address": "127.0.0.1",
					"port": 80,
					"users": [
						{
							"id": "e641f5ad-9397-41e3-bf1a-e8740dfed019",
							"email": "love@example.com",
							"level": 255
						}
					]
				}]
			}`,
			Parser: loadJSON(creator),
			Output: &outbound.Config{
				Receiver: &protocol.ServerEndpoint{
					Address: &net.IPOrDomain{
						Address: &net.IPOrDomain_Ip{
							Ip: []byte{127, 0, 0, 1},
						},
					},
					Port: 80,
					User: &protocol.User{
						Email: "love@example.com",
						Level: 255,
						Account: serial.ToTypedMessage(&vmess.Account{
							Id: "e641f5ad-9397-41e3-bf1a-e8740dfed019",
							SecuritySettings: &protocol.SecurityConfig{
								Type: protocol.SecurityType_AUTO,
							},
						}),
					},
				},
			},
		},
		{
			Input: `{
				"address": "127.0.0.1",
				"port": 80,
				"id": "e641f5ad-9397-41e3-bf1a-e8740dfed019",
				"email": "love@example.com",
				"level": 255
			}`,
			Parser: loadJSON(creator),
			Output: &outbound.Config{
				Receiver: &protocol.ServerEndpoint{
					Address: &net.IPOrDomain{
						Address: &net.IPOrDomain_Ip{
							Ip: []byte{127, 0, 0, 1},
						},
					},
					Port: 80,
					User: &protocol.User{
						Email: "love@example.com",
						Level: 255,
						Account: serial.ToTypedMessage(&vmess.Account{
							Id: "e641f5ad-9397-41e3-bf1a-e8740dfed019",
							SecuritySettings: &protocol.SecurityConfig{
								Type: protocol.SecurityType_AUTO,
							},
						}),
					},
				},
			},
		},
	})
}

func TestVMessInbound(t *testing.T) {
	creator := func() Buildable {
		return new(VMessInboundConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"clients": [
					{
						"id": "27848739-7e62-4138-9fd3-098a63964b6b",
						"level": 0,
						"email": "love@example.com",
						"security": "aes-128-gcm"
					}
				],
				"default": {
					"level": 0
				}
			}`,
			Parser: loadJSON(creator),
			Output: &inbound.Config{
				User: []*protocol.User{
					{
						Level: 0,
						Email: "love@example.com",
						Account: serial.ToTypedMessage(&vmess.Account{
							Id: "27848739-7e62-4138-9fd3-098a63964b6b",
							SecuritySettings: &protocol.SecurityConfig{
								Type: protocol.SecurityType_AES128_GCM,
							},
						}),
					},
				},
				Default: &inbound.DefaultConfig{
					Level: 0,
				},
			},
		},
	})
}
