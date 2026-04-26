package geodata_test

import (
	"path/filepath"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
)

func TestParseIPRules(t *testing.T) {
	t.Setenv("xray.location.asset", filepath.Join("..", "..", "resources"))

	rules := []string{
		"geoip:us",
		"geoip:cn",
		"!geoip:cn",
		"!!geoip:cn",
		"geoip:!cn",
		"geoip:!!cn",
		"!geoip:!cn",
		"ext:geoip.dat:!cn",
		"ext:geoip.dat:!!cn",
		"ext:geoip.dat:ca",
		"ext-ip:geoip.dat:!cn",
		"ext-ip:geoip.dat:!ca",
		"192.168.0.0/24",
		"!192.168.0.0/24",
		"!!192.168.0.0/24",
		"!!!192.168.0.0/24",
		"192.168.0.1",
		"fe80::/64",
		"fe80::",
	}

	_, err := geodata.ParseIPRules(rules)
	if err != nil {
		t.Fatalf("Failed to parse ip rules, got %s", err)
	}
}

func TestParseIPRuleReverse(t *testing.T) {
	t.Setenv("xray.location.asset", filepath.Join("..", "..", "resources"))

	for _, tt := range []struct {
		rule    string
		reverse bool
	}{
		{rule: "!192.168.0.0/24", reverse: true},
		{rule: "!!192.168.0.0/24", reverse: false},
		{rule: "!!!192.168.0.0/24", reverse: true},
		{rule: "!!!!192.168.0.0/24", reverse: false},
		{rule: "geoip:cn", reverse: false},
		{rule: "!geoip:cn", reverse: true},
		{rule: "!!geoip:cn", reverse: false},
		{rule: "geoip:!cn", reverse: true},
		{rule: "geoip:!!cn", reverse: false},
		{rule: "!geoip:!cn", reverse: false},
		{rule: "!!geoip:!cn", reverse: true},
		{rule: "!geoip:!!cn", reverse: true},
		{rule: "ext:geoip.dat:!!!cn", reverse: true},
	} {
		t.Run(tt.rule, func(t *testing.T) {
			rules, err := geodata.ParseIPRules([]string{tt.rule})
			if err != nil {
				t.Fatalf("Failed to parse ip rules, got %s", err)
			}

			if len(rules) != 1 {
				t.Fatalf("Expected 1 rule, got %d", len(rules))
			}

			switch rule := rules[0]; {
			case rule.GetGeoip() != nil:
				if rule.GetGeoip().GetReverseMatch() != tt.reverse {
					t.Fatalf("Expected geoip reverse match to be %t", tt.reverse)
				}
			case rule.GetCustom() != nil:
				if rule.GetCustom().GetReverseMatch() != tt.reverse {
					t.Fatalf("Expected custom reverse match to be %t", tt.reverse)
				}
			default:
				t.Fatal("Expected ip rule")
			}
		})
	}
}

func TestParseDomainRules(t *testing.T) {
	t.Setenv("xray.location.asset", filepath.Join("..", "..", "resources"))

	rules := []string{
		"geosite:cn",
		"geosite:geolocation-!cn",
		"geosite:cn@!cn",
		"ext:geosite.dat:geolocation-!cn",
		"ext:geosite.dat:cn@!cn",
		"ext-site:geosite.dat:geolocation-!cn",
		"ext-site:geosite.dat:cn@!cn",
		"domain:google.com",
	}

	_, err := geodata.ParseDomainRules(rules, geodata.Domain_Domain)
	if err != nil {
		t.Fatalf("Failed to parse domain rules, got %s", err)
	}
}
