package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/proxy/vless/outbound"
)

func TestVLessDeviceIDConfig(t *testing.T) {
	const id = "27848739-7e62-4138-9fd3-098a63964b6b"
	for name, input := range map[string]string{
		"simplified": `{"address":"example.com","port":443,"id":"` + id + `","encryption":"none","deviceId":"device-a"}`,
		"vnext":      `{"vnext":[{"address":"example.com","port":443,"users":[{"id":"` + id + `","encryption":"none","deviceId":"device-a"}]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			var config VLessOutboundConfig
			if err := json.Unmarshal([]byte(input), &config); err != nil {
				t.Fatal(err)
			}
			built, err := config.Build()
			if err != nil {
				t.Fatal(err)
			}
			user, err := built.(*outbound.Config).Vnext.User.ToMemoryUser()
			if err != nil {
				t.Fatal(err)
			}
			if user.Account.(*vless.MemoryAccount).DeviceID != "device-a" {
				t.Fatal("outbound configuration lost device ID")
			}
		})
	}
	for _, field := range []string{"users", "clients"} {
		t.Run(field, func(t *testing.T) {
			input := `{"decryption":"none","` + field + `":[{"id":"` + id + `","enforceDeviceId":true,"allowedDeviceIds":["device-a"]}]}`
			var config VLessInboundConfig
			if err := json.Unmarshal([]byte(input), &config); err != nil {
				t.Fatal(err)
			}
			built, err := config.Build()
			if err != nil {
				t.Fatal(err)
			}
			user, err := built.(*inbound.Config).Users[0].ToMemoryUser()
			if err != nil {
				t.Fatal(err)
			}
			account := user.Account.(*vless.MemoryAccount)
			if !account.AllowsDeviceID("device-a") || account.AllowsDeviceID("device-b") || account.AllowsDeviceID("") {
				t.Fatal("inbound configuration lost device policy")
			}
		})
	}
}

func TestVLessOutbound(t *testing.T) {
	creator := func() Buildable {
		return new(VLessOutboundConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"vnext": [{
					"address": "example.com",
					"port": 443,
					"users": [
						{
							"id": "27848739-7e62-4138-9fd3-098a63964b6b",
							"flow": "xtls-rprx-vision-udp443",
							"encryption": "none",
							"level": 0
						}
					]
				}]
			}`,
			Parser: loadJSON(creator),
			Output: &outbound.Config{
				Vnext: &protocol.ServerEndpoint{
					Address: &net.IPOrDomain{
						Address: &net.IPOrDomain_Domain{
							Domain: "example.com",
						},
					},
					Port: 443,
					User: &protocol.User{
						Account: serial.ToTypedMessage(&vless.Account{
							Id:         "27848739-7e62-4138-9fd3-098a63964b6b",
							Flow:       "xtls-rprx-vision-udp443",
							Encryption: "none",
						}),
						Level: 0,
					},
				},
			},
		},
		{
			Input: `{
				"address": "example.com",
				"port": 443,
				"id": "27848739-7e62-4138-9fd3-098a63964b6b",
				"flow": "xtls-rprx-vision-udp443",
				"encryption": "none",
				"level": 0
			}`,
			Parser: loadJSON(creator),
			Output: &outbound.Config{
				Vnext: &protocol.ServerEndpoint{
					Address: &net.IPOrDomain{
						Address: &net.IPOrDomain_Domain{
							Domain: "example.com",
						},
					},
					Port: 443,
					User: &protocol.User{
						Account: serial.ToTypedMessage(&vless.Account{
							Id:         "27848739-7e62-4138-9fd3-098a63964b6b",
							Flow:       "xtls-rprx-vision-udp443",
							Encryption: "none",
						}),
						Level: 0,
					},
				},
			},
		},
	})
}

func TestVLessInbound(t *testing.T) {
	creator := func() Buildable {
		return new(VLessInboundConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"clients": [
					{
						"id": "27848739-7e62-4138-9fd3-098a63964b6b",
						"flow": "xtls-rprx-vision",
						"level": 0,
						"email": "love@example.com"
					}
				],
				"decryption": "none",
				"fallbacks": [
					{
						"dest": 80
					},
					{
						"alpn": "h2",
						"dest": "@/dev/shm/domain.socket",
						"xver": 2
					},
					{
						"path": "/innerws",
						"dest": "serve-ws-none"
					}
				]
			}`,
			Parser: loadJSON(creator),
			Output: &inbound.Config{
				Users: []*protocol.User{
					{
						Account: serial.ToTypedMessage(&vless.Account{
							Id:   "27848739-7e62-4138-9fd3-098a63964b6b",
							Flow: "xtls-rprx-vision",
						}),
						Level: 0,
						Email: "love@example.com",
					},
				},
				Decryption: "none",
				Fallbacks: []*inbound.Fallback{
					{
						Alpn: "",
						Path: "",
						Type: "tcp",
						Dest: "localhost:80",
						Xver: 0,
					},
					{
						Alpn: "h2",
						Path: "",
						Type: "unix",
						Dest: "@/dev/shm/domain.socket",
						Xver: 2,
					},
					{
						Alpn: "",
						Path: "/innerws",
						Type: "serve",
						Dest: "serve-ws-none",
						Xver: 0,
					},
				},
			},
		},
	})
}
