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
				Server: &net.Endpoint{
					Network: net.Network_TCP,
					Address: net.NewIPOrDomain(net.IPAddress([]byte{8, 8, 8, 8})),
					Port:    53,
				},
				BlockMatched:  true,
				RejectBlocked: true,
			},
		},
		{
			Input: `{
				"blockMethod": "drop"
			}`,
			Parser: loadJSON(creator),
			Output: &dns.Config{
				Server:       &net.Endpoint{},
				BlockMatched: true,
			},
		},
		{
			Input: `{
				"blacklist": {
					"1,3,23-24": null,
					"28": ["domain:example.com", "full:example.com"]
				}
			}`,
			Parser: loadJSON(creator),
			Output: &dns.Config{
				Server:        &net.Endpoint{},
				BlockMatched:  true,
				RejectBlocked: true,
				QueryRule: []*dns.Config_QueryRule{
					{Qtype: 1},
					{Qtype: 3},
					{Qtype: 23},
					{Qtype: 24},
					{
						Qtype: 28,
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
				"whitelist": {
					"1,3,23-24": null,
					"28": "keyword:example"
				}
			}`,
			Parser: loadJSON(creator),
			Output: &dns.Config{
				Server:        &net.Endpoint{},
				RejectBlocked: true,
				QueryRule: []*dns.Config_QueryRule{
					{Qtype: 1},
					{Qtype: 3},
					{Qtype: 23},
					{Qtype: 24},
					{
						Qtype: 28,
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
				"blockMethod": "drop",
				"whitelist": {}
			}`,
			Parser: loadJSON(creator),
			Output: &dns.Config{
				Server: &net.Endpoint{},
			},
		},
		{
			Input: `{
				"nonIPQuery": "drop",
				"blockTypes": []
			}`,
			Parser: loadJSON(creator),
			Output: &dns.Config{
				Server: &net.Endpoint{},
				QueryRule: []*dns.Config_QueryRule{
					{Qtype: 1},
					{Qtype: 28},
				},
			},
		},
		{
			Input: `{
				"blockTypes": []
			}`,
			Parser: loadJSON(creator),
			Output: &dns.Config{
				Server:        &net.Endpoint{},
				RejectBlocked: true,
				QueryRule: []*dns.Config_QueryRule{
					{Qtype: 1},
					{Qtype: 28},
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
				Server: &net.Endpoint{},
				QueryRule: []*dns.Config_QueryRule{
					{Qtype: 28},
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
				Server:       &net.Endpoint{},
				BlockMatched: true,
				QueryRule: []*dns.Config_QueryRule{
					{Qtype: 28},
					{Qtype: 65},
				},
			},
		},
	})
}

func TestDnsProxyConfigRejectsMixedLists(t *testing.T) {
	creator := func() Buildable {
		return new(DNSOutboundConfig)
	}

	_, err := loadJSON(creator)(`{
		"blacklist": {"1": null},
		"whitelist": {"28": null}
	}`)
	if err == nil || !strings.Contains(err.Error(), `"blacklist" and "whitelist" are mutually exclusive`) {
		t.Fatal("expected mixed list error, but got ", err)
	}
}

func TestDnsProxyConfigRejectsMixedLegacyAndNewFields(t *testing.T) {
	creator := func() Buildable {
		return new(DNSOutboundConfig)
	}

	_, err := loadJSON(creator)(`{
		"blockMethod": "reject",
		"blockTypes": [65]
	}`)
	if err == nil || !strings.Contains(err.Error(), `legacy "nonIPQuery" and "blockTypes" cannot be mixed`) {
		t.Fatal("expected mixed legacy/new config error, but got ", err)
	}
}
