package conf_test

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask/ipfilter"
)

func TestFinalMaskIPFilter(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			input := fmt.Sprintf(`{"finalmask":{"%s":[{"type":"ip-filter","settings":{"blockedIPs":["192.0.2.0/24"]}}]}}`, network)
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
			if len(filter.BlockedIps) != 1 {
				t.Fatalf("expected one blocked IP rule, got %d", len(filter.BlockedIps))
			}
			cidr := filter.BlockedIps[0].GetCustom().GetCidr()
			if cidr.GetPrefix() != 24 || !net.IP(cidr.GetIp()).Equal(net.IPv4(192, 0, 2, 0)) {
				t.Fatalf("unexpected blocked IP rule: %v", cidr)
			}
			if _, err := internet.ToMemoryStreamConfig(built); err != nil {
				t.Fatalf("failed to initialize runtime finalmask: %v", err)
			}
		})
	}
	if _, err := (&IPFilter{BlockedIPs: []string{"192.0.2.0/33"}}).Build(); err == nil || !strings.Contains(err.Error(), "blockedIPs") {
		t.Errorf("expected invalid blockedIPs, got %v", err)
	}
}
