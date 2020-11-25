package conf_test

import (
	"testing"

	"github.com/xtls/xray-core/v1/common/net"
	"github.com/xtls/xray-core/v1/common/protocol"
	"github.com/xtls/xray-core/v1/common/serial"
	. "github.com/xtls/xray-core/v1/infra/conf"
	"github.com/xtls/xray-core/v1/proxy/shadowsocks"
)

func TestShadowsocksServerConfigParsing(t *testing.T) {
	creator := func() Buildable {
		return new(ShadowsocksServerConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"method": "aes-128-cfb",
				"password": "xray-password"
			}`,
			Parser: loadJSON(creator),
			Output: &shadowsocks.ServerConfig{
				User: &protocol.User{
					Account: serial.ToTypedMessage(&shadowsocks.Account{
						CipherType: shadowsocks.CipherType_AES_128_CFB,
						Password:   "xray-password",
					}),
				},
				Network: []net.Network{net.Network_TCP},
			},
		},
	})
}
