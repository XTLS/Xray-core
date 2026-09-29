package conf_test

import (
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/tun"
)

func TestTunConfigAutoSystemWFP(t *testing.T) {
	creator := func() Buildable {
		return new(TunConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input:  `{"name": "xray0"}`,
			Parser: loadJSON(creator),
			Output: &tun.Config{Name: "xray0", Desc: "Wintun", MTU: 1500},
		},
		{
			Input:  `{"name": "xray0", "autoSystemWFP": true}`,
			Parser: loadJSON(creator),
			Output: &tun.Config{Name: "xray0", Desc: "Wintun", MTU: 1500, AutoSystemWfp: true},
		},
	})
}
