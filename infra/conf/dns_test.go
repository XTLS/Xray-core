package conf_test

import (
	"encoding/json"
	"strings"
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

func TestDNSNameServerID(t *testing.T) {
	var parsed DNSConfig
	if err := json.Unmarshal([]byte(`{"servers":[{"id":"primary","address":"1.1.1.1"}]}`), &parsed); err != nil {
		t.Fatal(err)
	}
	built, err := parsed.Build()
	if err != nil {
		t.Fatal(err)
	}
	if len(built.NameServer) != 1 || built.NameServer[0].Id != "primary" {
		t.Fatalf("nameserver IDs = %v, want primary", built.NameServer)
	}
}

func TestDNSScriptConfig(t *testing.T) {
	for _, test := range []struct {
		name      string
		input     string
		wantError string
	}{
		{name: "script only", input: `{"script":"script.lua"}`},
		{name: "compatible fields", input: `{"script":"script.lua","servers":["1.1.1.1",{"id":"primary","address":"8.8.8.8","expectedIPs":["8.8.8.8"],"queryStrategy":"UseIPv4","disableCache":true}],"hosts":{"example.com":"127.0.0.1"},"disableCache":true}`},
		{name: "disabled options", input: `{"script":"script.lua","disableFallback":false,"disableFallbackIfMatch":false,"enableParallelQuery":false,"servers":[{"address":"1.1.1.1","domains":[],"skipFallback":false,"finalQuery":false}]}`},
		{name: "domains", input: `{"script":"script.lua","servers":[{"address":"1.1.1.1","domains":["domain:example.com"]}]}`, wantError: "domains"},
		{name: "skip fallback", input: `{"script":"script.lua","servers":[{"address":"1.1.1.1","skipFallback":true}]}`, wantError: "skipFallback"},
		{name: "final query", input: `{"script":"script.lua","servers":[{"address":"1.1.1.1","finalQuery":true}]}`, wantError: "finalQuery"},
		{name: "later server", input: `{"script":"script.lua","servers":["1.1.1.1",{"address":"8.8.8.8","finalQuery":true}]}`, wantError: "server 1"},
		{name: "disable fallback", input: `{"script":"script.lua","disableFallback":true}`, wantError: "disableFallback"},
		{name: "disable fallback if match", input: `{"script":"script.lua","disableFallbackIfMatch":true}`, wantError: "disableFallbackIfMatch"},
		{name: "parallel query", input: `{"script":"script.lua","enableParallelQuery":true}`, wantError: "enableParallelQuery"},
		{name: "empty script", input: `{"script":"","disableFallback":true,"disableFallbackIfMatch":true,"enableParallelQuery":true,"servers":[{"address":"1.1.1.1","domains":["example.com"],"skipFallback":true,"finalQuery":true}]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var config DNSConfig
			if err := json.Unmarshal([]byte(test.input), &config); err != nil {
				t.Fatal(err)
			}
			built, err := config.Build()
			if test.wantError != "" {
				if built != nil || err == nil || !strings.Contains(err.Error(), "DNS script cannot be used with ") || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("Build() = %v, %v; want nil config and script conflict error mentioning %s", built, err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if built.Script != config.Script || len(built.NameServer) != len(config.Servers) {
				t.Fatalf("Build() did not preserve script or servers: %v", built)
			}
		})
	}
}
