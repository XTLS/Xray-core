package conf_test

import (
	"encoding/json"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/tun"
)

func TestTunConfigAutoSystem(t *testing.T) {
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
			Input:  `{"name": "xray0", "autoSystemDnsToGateway": true}`,
			Parser: loadJSON(creator),
			Output: &tun.Config{Name: "xray0", Desc: "Wintun", MTU: 1500, AutoSystemDnsToGateway: true},
		},
		{
			Input:  `{"name": "xray0", "autoSystemWfpBlockLeak": ["dns", "misconfig"]}`,
			Parser: loadJSON(creator),
			Output: &tun.Config{Name: "xray0", Desc: "Wintun", MTU: 1500, AutoSystemWfpBlockLeak: []string{"dns", "misconfig"}},
		},
		{
			Input:  `{"name": "xray0", "autoSystemWfpBlockLeak": ["DNS"]}`,
			Parser: loadJSON(creator),
			Output: &tun.Config{Name: "xray0", Desc: "Wintun", MTU: 1500, AutoSystemWfpBlockLeak: []string{"dns"}},
		},
	})
}

func TestTunConfigAutoSystemWfpBlockLeakUnknown(t *testing.T) {
	config := new(TunConfig)
	if err := json.Unmarshal([]byte(`{"name": "xray0", "autoSystemWfpBlockLeak": ["dns", "ip"]}`), config); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Build(); err == nil {
		t.Error("an unknown autoSystemWfpBlockLeak value was accepted")
	}
}
