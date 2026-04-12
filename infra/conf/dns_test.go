package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	. "github.com/xtls/xray-core/infra/conf"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestDNSConfigParsing(t *testing.T) {
	parserCreator := func() func(string) (proto.Message, error) {
		return func(s string) (proto.Message, error) {
			config := new(DNSConfig)
			if err := json.Unmarshal([]byte(s), config); err != nil {
				return nil, err
			}
			return config.Build()
		}
	}
	expectedServeStale := true
	expectedServeExpiredTTL := uint32(172800)
	testCases := []TestCase{
		{
			Input: `{
				"servers": [{
					"address": "8.8.8.8",
					"port": 5353,
					"skipFallback": true,
					"domains": ["domain:example.com"],
					"serveStale": true,
					"serveExpiredTTL": 172800
				}],
				"hosts": {
					"domain:example.com": "google.com",
					"example.com": "127.0.0.1",
					"keyword:google": ["8.8.8.8", "8.8.4.4"],
					"regexp:.*\\.com": "8.8.4.4",
					"www.example.org": ["127.0.0.1", "127.0.0.2"]
				},
				"clientIp": "10.0.0.1",
				"queryStrategy": "UseIPv4",
				"disableCache": true,
				"serveStale": false,
				"serveExpiredTTL": 86400,
				"disableFallback": true
			}`,
			Parser: parserCreator(),
			Output: &dns.Config{
				NameServer: []*dns.NameServer{
					{
						Address: &net.Endpoint{
							Address: &net.IPOrDomain{
								Address: &net.IPOrDomain_Ip{
									Ip: []byte{8, 8, 8, 8},
								},
							},
							Network: net.Network_UDP,
							Port:    5353,
						},
						SkipFallback: true,
						Domain: []*geodata.DomainRule{
							{
								Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Domain, Value: "example.com"}},
							},
						},
						ServeStale:      &expectedServeStale,
						ServeExpiredTTL: &expectedServeExpiredTTL,
						PolicyID:        1, // Servers with certain identical fields share this ID, incrementing starting from 1. See: Build PolicyID
					},
				},
				StaticHosts: []*dns.Config_HostMapping{
					{
						Domain:        &geodata.DomainRule{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Domain, Value: "example.com"}}},
						ProxiedDomain: "google.com",
					},
					{
						Domain: &geodata.DomainRule{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: "example.com"}}},
						Ip:     [][]byte{{127, 0, 0, 1}},
					},
					{
						Domain: &geodata.DomainRule{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Substr, Value: "google"}}},
						Ip:     [][]byte{{8, 8, 8, 8}, {8, 8, 4, 4}},
					},
					{
						Domain: &geodata.DomainRule{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Regex, Value: ".*\\.com"}}},
						Ip:     [][]byte{{8, 8, 4, 4}},
					},
					{
						Domain: &geodata.DomainRule{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: "www.example.org"}}},
						Ip:     [][]byte{{127, 0, 0, 1}, {127, 0, 0, 2}},
					},
				},
				ClientIp:        []byte{10, 0, 0, 1},
				QueryStrategy:   dns.QueryStrategy_USE_IP4,
				DisableCache:    true,
				ServeStale:      false,
				ServeExpiredTTL: 86400,
				DisableFallback: true,
			},
		},
	}

	for _, testCase := range testCases {
		actual, err := testCase.Parser(testCase.Input)
		if err != nil {
			t.Fatal(err)
		}

		if diff := cmp.Diff(
			testCase.Output,
			actual,
			protocmp.Transform(),
			protocmp.SortRepeatedFields(&dns.Config{}, "static_hosts"),
		); diff != "" {
			t.Fatalf("Failed in test case:\n%s\nDiff (-want +got):\n%s", testCase.Input, diff)
		}
	}
}
