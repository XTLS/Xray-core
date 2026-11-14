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
			Output: &tun.Config{Name: "xray0", Desc: "Wintun", MTU: 1500, DNS: []string{"1.1.1.1"}, AutoSystemRoutingTable: []string{"0.0.0.0/0"}, AutoOutboundsInterface: "auto", AutoSystemWfpBlockLeak: []string{"53", "853", "windnsclient", "misconfigtun"}},
		},
		{
			Input:  `{"name": "xray0", "dns": ["1.1.1.1"], "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["DNS"]}`,
			Parser: loadJSON(creator),
			Output: &tun.Config{Name: "xray0", Desc: "Wintun", MTU: 1500, DNS: []string{"1.1.1.1"}, AutoSystemRoutingTable: []string{"0.0.0.0/0"}, AutoOutboundsInterface: "auto", AutoSystemWfpBlockLeak: []string{"53", "853", "windnsclient"}},
		},
		{
			Input:  `{"name": "xray0", "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["TCP/853", "udp/853", "tcp/0853"]}`,
			Parser: loadJSON(creator),
			Output: &tun.Config{Name: "xray0", Desc: "Wintun", MTU: 1500, AutoSystemRoutingTable: []string{"0.0.0.0/0"}, AutoOutboundsInterface: "auto", AutoSystemWfpBlockLeak: []string{"tcp/853", "udp/853"}},
		},
		{
			Input:  `{"name": "xray0", "dns": ["1.1.1.1"], "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["All", "UDP", "tcp/8000-9000", "icmp"]}`,
			Parser: loadJSON(creator),
			Output: &tun.Config{Name: "xray0", Desc: "Wintun", MTU: 1500, DNS: []string{"1.1.1.1"}, AutoSystemRoutingTable: []string{"0.0.0.0/0"}, AutoOutboundsInterface: "auto", AutoSystemWfpBlockLeak: []string{"all", "udp", "tcp/8000-9000", "icmp"}},
		},
		{
			Input:  `{"name": "xray0", "dns": ["1.1.1.1"], "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["AllExceptLAN"]}`,
			Parser: loadJSON(creator),
			Output: &tun.Config{Name: "xray0", Desc: "Wintun", MTU: 1500, DNS: []string{"1.1.1.1"}, AutoSystemRoutingTable: []string{"0.0.0.0/0"}, AutoOutboundsInterface: "auto", AutoSystemWfpBlockLeak: []string{"allexceptlan", "53", "853", "windnsclient"}},
		},
		{
			Input:  `{"name": "xray0", "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["1.1.1.1/24:TCP/853", "[2001:DB8::/32]:udp/10-20", "[::/0]:ICMP", "853"]}`,
			Parser: loadJSON(creator),
			Output: &tun.Config{Name: "xray0", Desc: "Wintun", MTU: 1500, AutoSystemRoutingTable: []string{"0.0.0.0/0"}, AutoOutboundsInterface: "auto", AutoSystemWfpBlockLeak: []string{"1.1.1.0/24:tcp/853", "[2001:db8::/32]:udp/10-20", "[::/0]:icmp", "853"}},
		},
		{
			Input:  `{"name": "xray0", "dns": ["1.1.1.1"], "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["0.0.0.0/0:dns", "[::/0]:All", "53"]}`,
			Parser: loadJSON(creator),
			Output: &tun.Config{Name: "xray0", Desc: "Wintun", MTU: 1500, DNS: []string{"1.1.1.1"}, AutoSystemRoutingTable: []string{"0.0.0.0/0"}, AutoOutboundsInterface: "auto", AutoSystemWfpBlockLeak: []string{"0.0.0.0/0:53", "0.0.0.0/0:853", "0.0.0.0/0:windnsclient", "[::/0]:all", "53"}},
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
		{`{"name": "xray0", "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["all"]}`, []string{"windows"}},
		{`{"name": "xray0", "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["udp"]}`, []string{"windows"}},
		{`{"name": "xray0", "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["tcp/50-60"]}`, []string{"windows"}},
		{`{"name": "xray0", "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["tcp/54-60", "icmp"]}`, nil},
		{`{"name": "xray0", "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["53"]}`, []string{"windows"}},
		{`{"name": "xray0", "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["50-60"]}`, []string{"windows"}},
		{`{"name": "xray0", "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["[::/0]:udp/53"]}`, []string{"windows"}},
		{`{"name": "xray0", "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["1.1.1.1/32:dns"]}`, []string{"windows"}},
		{`{"name": "xray0", "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["[2001:db8::/32]:all"]}`, []string{"windows"}},
		{`{"name": "xray0", "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["0.0.0.0/0:windnsclient"]}`, []string{"windows"}},
		{`{"name": "xray0", "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["0.0.0.0/0:tcp/853", "1.1.1.0/24:icmp", "[::/0]:misconfigtun", "54-60"]}`, nil},
		{`{"name": "xray0", "autoSystemWfpBlockLeak": ["[::/0]:misconfigtun"]}`, []string{"windows"}},
		{`{"name": "xray0", "autoSystemWfpBlockLeak": ["all"]}`, []string{"windows"}},
		{`{"name": "xray0", "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["allexceptlan"]}`, []string{"windows"}},
		{`{"name": "xray0", "dns": ["1.1.1.1"], "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["allexceptlan"]}`, nil},
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
	// With the settings the values need on Windows, so that only an unknown
	// one fails.
	build := func(value string) error {
		config := new(TunConfig)
		if err := json.Unmarshal([]byte(`{"name": "xray0", "dns": ["1.1.1.1"], "autoSystemRoutingTable": ["0.0.0.0/0"], "autoSystemWfpBlockLeak": ["dns", "`+value+`"]}`), config); err != nil {
			t.Fatal(err)
		}
		_, err := config.Build()
		return err
	}
	if err := build("1.1.1.0/24:53"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"ip", "tcp/0", "tcp/0-10", "icmp/1", "udp/20-10", "0", "20-10", "53/tcp", "tcpv4", "ipv4:udp", "1.1.1.1:53", "2001:db8::/32:53", "[1.1.1.0/24]:53", "[::ffff:1.1.1.0/120]:53", "1.1.1.0/24"} {
		if build(value) == nil {
			t.Errorf("autoSystemWfpBlockLeak value %q was accepted", value)
		}
	}
}
