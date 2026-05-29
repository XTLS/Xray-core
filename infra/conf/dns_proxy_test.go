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
					"qtype": "1,3,23-24"
				}, {
					"action": "drop",
					"qtype": 28,
					"domain": ["domain:example.com", "full:example.com"]
				}]
			}`,
			Parser: loadJSON(creator),
			Output: &dns.Config{
				RewriteServer: &net.Endpoint{},
				Rule: []*dns.DNSRuleConfig{
					{
						Action: dns.RuleAction_Direct,
						Qtype:  []int32{1, 3, 23, 24},
					},
					{
						Action: dns.RuleAction_Drop,
						Qtype:  []int32{28},
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
					"action": "reject",
					"domain": "keyword:example"
				}]
			}`,
			Parser: loadJSON(creator),
			Output: &dns.Config{
				RewriteServer: &net.Endpoint{},
				Rule: []*dns.DNSRuleConfig{
					{
						Action: dns.RuleAction_Reject,
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
					"qtype": 257
				}]
			}`,
			Parser: loadJSON(creator),
			Output: &dns.Config{
				RewriteServer: &net.Endpoint{},
				Rule: []*dns.DNSRuleConfig{
					{
						Action: dns.RuleAction_Drop,
						Qtype:  []int32{257},
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
						Qtype:  []int32{1, 28},
					},
					{
						Action: dns.RuleAction_Reject,
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
						Action: dns.RuleAction_Reject,
						Qtype:  []int32{1, 65},
					},
					{
						Action: dns.RuleAction_Hijack,
						Qtype:  []int32{1, 28},
					},
					{
						Action: dns.RuleAction_Reject,
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
						Qtype:  []int32{1},
					},
					{
						Action: dns.RuleAction_Hijack,
						Qtype:  []int32{1, 28},
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
						Qtype:  []int32{65, 28},
					},
					{
						Action: dns.RuleAction_Hijack,
						Qtype:  []int32{1, 28},
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
			"qtype": 65
		}],
		"blockTypes": [65]
	}`)
	if err == nil || !strings.Contains(err.Error(), `legacy nonIPQuery and blockTypes cannot be mixed with rules`) {
		t.Fatal("expected mixed legacy/new config error, but got ", err)
	}
}
