package conf_test

import (
	"bytes"
	"encoding/json"
	"strconv"
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

func TestDNSClientIPPrefix(t *testing.T) {
	var config DNSConfig
	input := `{"clientIp":"0.0.0.0/0","servers":["8.8.8.8",{"address":"1.1.1.1","clientIp":"1.2.3.4"},{"address":"9.9.9.9","clientIp":"2001:db8::1234/56"},{"address":"4.4.4.4","clientIp":"::/0"}]}`
	if err := json.Unmarshal([]byte(input), &config); err != nil {
		t.Fatal(err)
	}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(built.ClientIp, []byte{0, 0, 0, 0}) || built.ClientIpPrefix == nil || *built.ClientIpPrefix != 0 {
		t.Fatalf("global clientIp = %v/%v", built.ClientIp, built.ClientIpPrefix)
	}
	if built.NameServer[0].ClientIpPrefix != nil || built.NameServer[1].ClientIpPrefix != nil || !bytes.Equal(built.NameServer[1].ClientIp, []byte{1, 2, 3, 4}) {
		t.Fatalf("bare nameserver clientIp values changed: %v", built.NameServer)
	}
	if built.NameServer[2].ClientIpPrefix == nil || *built.NameServer[2].ClientIpPrefix != 56 || !bytes.Equal(built.NameServer[2].ClientIp, net.ParseIP("2001:db8::1234")) {
		t.Fatalf("IPv6 nameserver clientIp = %v/%v", built.NameServer[2].ClientIp, built.NameServer[2].ClientIpPrefix)
	}
	if built.NameServer[3].ClientIpPrefix == nil || *built.NameServer[3].ClientIpPrefix != 0 || !bytes.Equal(built.NameServer[3].ClientIp, net.ParseIP("::")) {
		t.Fatalf("IPv6 wildcard clientIp = %v/%v", built.NameServer[3].ClientIp, built.NameServer[3].ClientIpPrefix)
	}
	wire, err := proto.Marshal(built)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip dns.Config
	if err := proto.Unmarshal(wire, &roundTrip); err != nil || roundTrip.ClientIpPrefix == nil || *roundTrip.ClientIpPrefix != 0 {
		t.Fatalf("lost explicit /0 in protobuf: %v, %v", roundTrip.ClientIpPrefix, err)
	}
	for _, tc := range []struct {
		value string
		ip    []byte
		bits  uint32
	}{
		{"1.2.3.4/24", []byte{1, 2, 3, 4}, 24},
		{"1.2.3.4/20", []byte{1, 2, 3, 4}, 20},
		{"2001:db8::1/96", net.ParseIP("2001:db8::1"), 96},
	} {
		var explicit DNSConfig
		if err := json.Unmarshal([]byte(`{"clientIp":`+strconv.Quote(tc.value)+`}`), &explicit); err != nil {
			t.Fatal(err)
		}
		got, err := explicit.Build()
		if err != nil || !bytes.Equal(got.ClientIp, tc.ip) || got.ClientIpPrefix == nil || *got.ClientIpPrefix != tc.bits {
			t.Fatalf("clientIp %q: got %v, %v", tc.value, got, err)
		}
	}

	for _, value := range []string{"1.2.3.4/33", "2001:db8::1/129", "example.com"} {
		for _, server := range []bool{false, true} {
			input := `{"clientIp":` + strconv.Quote(value) + `}`
			if server {
				input = `{"servers":[{"address":"8.8.8.8","clientIp":` + strconv.Quote(value) + `}]}`
			}
			var invalid DNSConfig
			if err := json.Unmarshal([]byte(input), &invalid); err != nil {
				t.Fatal(err)
			}
			if _, err := invalid.Build(); err == nil {
				t.Errorf("accepted invalid clientIp %q (server=%t)", value, server)
			}
		}
	}
}
