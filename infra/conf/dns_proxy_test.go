package conf_test

import (
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/dns"
)

func TestDnsProxyConfig(t *testing.T) {
	creator := func() Buildable {
		return new(DNSOutboundConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"address": "8.8.8.8",
				"port": 53,
				"network": "tcp"
			}`,
			Parser: loadJSON(creator),
			Output: &dns.Config{
				RewriteServer: &net.Endpoint{
					Network: net.Network_TCP,
					Address: net.NewIPOrDomain(net.IPAddress([]byte{8, 8, 8, 8})),
					Port:    53,
				},
			},
		},
		{
			Input: `{
				"rules": [{
					"action": "direct",
					"qType": "1,3,23-24"
				}, {
					"action": "drop",
					"qType": 28,
					"domain": ["domain:example.com", "full:example.com"]
				}]
			}`,
			Parser: loadJSON(creator),
			Output: &dns.Config{
				RewriteServer: &net.Endpoint{},
				Rule: []*dns.DNSRuleConfig{
					{
						Action: dns.RuleAction_Direct,
						QType:  []int32{1, 3, 23, 24},
					},
					{
						Action: dns.RuleAction_Drop,
						QType:  []int32{28},
						Domain: []*geodata.DomainRule{
							{
								Value: &geodata.DomainRule_Custom{
									Custom: &geodata.Domain{
										Type:  geodata.Domain_Domain,
										Value: "example.com",
									},
								},
							},
							{
								Value: &geodata.DomainRule_Custom{
									Custom: &geodata.Domain{
										Type:  geodata.Domain_Full,
										Value: "example.com",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			Input: `{
				"rules": [{
					"action": "return",
					"rCode": 5,
					"domain": "keyword:example"
				}]
			}`,
			Parser: loadJSON(creator),
			Output: &dns.Config{
				RewriteServer: &net.Endpoint{},
				Rule: []*dns.DNSRuleConfig{
					{
						Action: dns.RuleAction_Return,
						RCode:  5,
						Domain: []*geodata.DomainRule{
							{
								Value: &geodata.DomainRule_Custom{
									Custom: &geodata.Domain{
										Type:  geodata.Domain_Substr,
										Value: "example",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			Input: `{
				"rules": [{
					"action": "drop",
					"qType": 257
				}]
			}`,
			Parser: loadJSON(creator),
			Output: &dns.Config{
				RewriteServer: &net.Endpoint{},
				Rule: []*dns.DNSRuleConfig{
					{
						Action: dns.RuleAction_Drop,
						QType:  []int32{257},
					},
				},
			},
		},
	})
}

// todo: remove legacy
func TestDnsProxyConfigLegacyCompatibility(t *testing.T) {
	creator := func() Buildable {
		return new(DNSOutboundConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"blockTypes": []
			}`,
			Parser: loadJSON(creator),
			Output: &dns.Config{
				RewriteServer: &net.Endpoint{},
				Rule: []*dns.DNSRuleConfig{
					{
						Action: dns.RuleAction_Hijack,
						QType:  []int32{1, 28},
					},
					{
						Action: dns.RuleAction_Return,
						RCode:  5,
					},
				},
			},
		},
		{
			Input: `{
				"blockTypes": [1, 65]
			}`,
			Parser: loadJSON(creator),
			Output: &dns.Config{
				RewriteServer: &net.Endpoint{},
				Rule: []*dns.DNSRuleConfig{
					{
						Action: dns.RuleAction_Return,
						QType:  []int32{1, 65},
						RCode:  5,
					},
					{
						Action: dns.RuleAction_Hijack,
						QType:  []int32{1, 28},
					},
					{
						Action: dns.RuleAction_Return,
						RCode:  5,
					},
				},
			},
		},
		{
			Input: `{
				"nonIPQuery": "drop",
				"blockTypes": [1]
			}`,
			Parser: loadJSON(creator),
			Output: &dns.Config{
				RewriteServer: &net.Endpoint{},
				Rule: []*dns.DNSRuleConfig{
					{
						Action: dns.RuleAction_Drop,
						QType:  []int32{1},
					},
					{
						Action: dns.RuleAction_Hijack,
						QType:  []int32{1, 28},
					},
					{
						Action: dns.RuleAction_Drop,
					},
				},
			},
		},
		{
			Input: `{
				"nonIPQuery": "skip",
				"blockTypes": [65, 28]
			}`,
			Parser: loadJSON(creator),
			Output: &dns.Config{
				RewriteServer: &net.Endpoint{},
				Rule: []*dns.DNSRuleConfig{
					{
						Action: dns.RuleAction_Drop,
						QType:  []int32{65, 28},
					},
					{
						Action: dns.RuleAction_Hijack,
						QType:  []int32{1, 28},
					},
					{
						Action: dns.RuleAction_Direct,
					},
				},
			},
		},
	})
}

// todo: remove legacy
func TestDnsProxyConfigRejectsMixedLegacyAndNewFields(t *testing.T) {
	creator := func() Buildable {
		return new(DNSOutboundConfig)
	}

	_, err := loadJSON(creator)(`{
		"rules": [{
			"action": "direct",
			"qType": 65
		}],
		"blockTypes": [65]
	}`)
	if err == nil || !strings.Contains(err.Error(), `legacy nonIPQuery and blockTypes cannot be mixed with rules`) {
		t.Fatal("expected mixed legacy/new config error, but got ", err)
	}
}
