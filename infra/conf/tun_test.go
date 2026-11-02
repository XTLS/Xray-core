package conf_test

import (
	"encoding/json"
	"runtime"
	"slices"
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
			Input:  `{"name": "xray0", "gateway": ["10.0.0.1/24"], "autoSystemDnsToGateway": true}`,
			Parser: loadJSON(creator),
			Output: &tun.Config{Name: "xray0", Desc: "Wintun", MTU: 1500, Gateway: []string{"10.0.0.1/24"}, AutoSystemDnsToGateway: true},
		},
		{
			Input:  `{"name": "xray0", "dns": ["1.1.1.1"], "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["dns", "misconfigtun"]}`,
			Parser: loadJSON(creator),
			Output: &tun.Config{Name: "xray0", Desc: "Wintun", MTU: 1500, DNS: []string{"1.1.1.1"}, AutoSystemRoutingTable: []string{"0.0.0.0/0"}, AutoOutboundsInterface: "auto", AutoSystemWfpBlockLeak: []string{"udp/53", "tcp/53", "windnsclient", "tcp/853", "udp/853", "misconfigtun"}},
		},
		{
			Input:  `{"name": "xray0", "dns": ["1.1.1.1"], "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["DNS"]}`,
			Parser: loadJSON(creator),
			Output: &tun.Config{Name: "xray0", Desc: "Wintun", MTU: 1500, DNS: []string{"1.1.1.1"}, AutoSystemRoutingTable: []string{"0.0.0.0/0"}, AutoOutboundsInterface: "auto", AutoSystemWfpBlockLeak: []string{"udp/53", "tcp/53", "windnsclient", "tcp/853", "udp/853"}},
		},
		{
			Input:  `{"name": "xray0", "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["TCP/853", "udp/853", "tcp/0853"]}`,
			Parser: loadJSON(creator),
			Output: &tun.Config{Name: "xray0", Desc: "Wintun", MTU: 1500, AutoSystemRoutingTable: []string{"0.0.0.0/0"}, AutoOutboundsInterface: "auto", AutoSystemWfpBlockLeak: []string{"tcp/853", "udp/853"}},
		},
	})
}

// TestTunConfigAutoSystemNeeds checks that an option is rejected without the
// setting it needs, only on the system it takes effect on.
func TestTunConfigAutoSystemNeeds(t *testing.T) {
	for _, c := range []struct {
		input string
		goos  []string // where it is rejected
	}{
		{`{"name": "xray0", "autoSystemWfpBlockLeak": ["misconfigtun"]}`, []string{"windows"}},
		{`{"name": "xray0", "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["misconfigtun"]}`, nil},
		{`{"name": "xray0", "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["dns"]}`, []string{"windows"}},
		{`{"name": "xray0", "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["udp/53"]}`, []string{"windows"}},
		{`{"name": "xray0", "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["windnsclient"]}`, []string{"windows"}},
		{`{"name": "xray0", "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["tcp/853", "udp/853"]}`, nil},
		{`{"name": "xray0", "autoSystemDnsToGateway": true}`, []string{"linux", "freebsd"}},
	} {
		config := new(TunConfig)
		if err := json.Unmarshal([]byte(c.input), config); err != nil {
			t.Fatal(err)
		}
		if _, err := config.Build(); (err != nil) != slices.Contains(c.goos, runtime.GOOS) {
			t.Errorf("%s on %s: error = %v", c.input, runtime.GOOS, err)
		}
	}
}

func TestTunConfigAutoSystemWfpBlockLeakUnknown(t *testing.T) {
	for _, value := range []string{"ip", "tcp/0", "icmp/1"} {
		config := new(TunConfig)
		if err := json.Unmarshal([]byte(`{"name": "xray0", "autoSystemWfpBlockLeak": ["dns", "`+value+`"]}`), config); err != nil {
			t.Fatal(err)
		}
		if _, err := config.Build(); err == nil {
			t.Errorf("autoSystemWfpBlockLeak value %q was accepted", value)
		}
	}
}
