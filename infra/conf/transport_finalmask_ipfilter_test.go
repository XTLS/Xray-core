package conf_test

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask/ipfilter"
)

func TestFinalMaskIPFilter(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, test := range []struct {
			name, settings   string
			blocked, allowed int
		}{
			{"blacklist", `{"blockedIPs":["192.0.2.0/24"]}`, 1, 0},
			{"whitelist", `{"allowedIPs":["192.0.2.0/24"]}`, 0, 1},
			{"both", `{"blockedIPs":["192.0.2.0/24"],"allowedIPs":["192.0.2.0/24"]}`, 1, 1},
			{"empty_whitelist", `{"allowedIPs":[]}`, 0, 0},
			{"empty_blacklist", `{"blockedIPs":[]}`, 0, 0},
		} {
			t.Run(network+"/"+test.name, func(t *testing.T) {
				input := fmt.Sprintf(`{"finalmask":{"%s":[{"type":"ip-filter","settings":%s}]}}`, network, test.settings)
				var config StreamConfig
				if err := json.Unmarshal([]byte(input), &config); err != nil {
					t.Fatal(err)
				}
				built, err := config.Build()
				if err != nil {
					t.Fatal(err)
				}
				masks := built.Tcpmasks
				if network == "udp" {
					masks = built.Udpmasks
				}
				if len(masks) != 1 {
					t.Fatalf("expected one mask, got %d", len(masks))
				}
				instance, err := masks[0].GetInstance()
				if err != nil {
					t.Fatal(err)
				}
				filter, ok := instance.(*ipfilter.Config)
				if !ok {
					t.Fatalf("unexpected mask type: %T", instance)
				}
				if len(filter.BlockedIps) != test.blocked || len(filter.AllowedIps) != test.allowed {
					t.Fatalf("unexpected IP filter policy: %v", filter)
				}
				for _, rules := range [][]*geodata.IPRule{filter.BlockedIps, filter.AllowedIps} {
					for _, rule := range rules {
						cidr := rule.GetCustom().GetCidr()
						if cidr.GetPrefix() != 24 || !net.IP(cidr.GetIp()).Equal(net.IPv4(192, 0, 2, 0)) {
							t.Fatalf("unexpected IP rule: %v", cidr)
						}
					}
				}
				if _, err := internet.ToMemoryStreamConfig(built); err != nil {
					t.Fatalf("failed to initialize runtime finalmask: %v", err)
				}
			})
		}
	}
	for _, field := range []string{"blockedIPs", "allowedIPs"} {
		var config IPFilter
		if err := json.Unmarshal([]byte(fmt.Sprintf(`{"%s":["192.0.2.0/33"]}`, field)), &config); err != nil {
			t.Fatal(err)
		}
		if _, err := config.Build(); err == nil || !strings.Contains(err.Error(), field) {
			t.Errorf("expected invalid %s, got %v", field, err)
		}
	}
}
