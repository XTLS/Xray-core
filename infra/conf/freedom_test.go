package conf_test

import (
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport/internet"
)

func TestFreedomConfig(t *testing.T) {
	creator := func() Buildable {
		return new(FreedomConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"domainStrategy": "AsIs",
				"redirect": "127.0.0.1:3366",
				"userLevel": 1
			}`,
			Parser: loadJSON(creator),
			Output: &freedom.Config{
				DomainStrategy: internet.DomainStrategy_AS_IS,
				DestinationOverride: &freedom.DestinationOverride{
					Server: &protocol.ServerEndpoint{
						Address: &net.IPOrDomain{
							Address: &net.IPOrDomain_Ip{
								Ip: []byte{127, 0, 0, 1},
							},
						},
						Port: 3366,
					},
				},
				UserLevel: 1,
			},
		},
		{
			Input: `{
				"finalRules": [{
					"action": "block",
					"network": "tcp,udp",
					"port": "53,443",
					"ip": ["10.0.0.0/8", "2001:db8::/32"],
					"blockDelay": "30-60"
				}, {
					"action": "allow",
					"network": ["udp"]
				}]
			}`,
			Parser: loadJSON(creator),
			Output: &freedom.Config{
				FinalRules: []*freedom.FinalRuleConfig{
					{
						Action:   freedom.RuleAction_Block,
						Networks: []net.Network{net.Network_TCP, net.Network_UDP},
						PortList: &net.PortList{
							Range: []*net.PortRange{
								{From: 53, To: 53},
								{From: 443, To: 443},
							},
						},
						Ip: []*geodata.IPRule{
							{
								Value: &geodata.IPRule_Custom{
									Custom: &geodata.CIDRRule{
										Cidr: &geodata.CIDR{
											Ip:     []byte{10, 0, 0, 0},
											Prefix: 8,
										},
									},
								},
							},
							{
								Value: &geodata.IPRule_Custom{
									Custom: &geodata.CIDRRule{
										Cidr: &geodata.CIDR{
											Ip:     net.ParseAddress("2001:db8::").IP(),
											Prefix: 32,
										},
									},
								},
							},
						},
						BlockDelay: &freedom.Range{
							Min: 30,
							Max: 60,
						},
					},
					{
						Action:   freedom.RuleAction_Allow,
						Networks: []net.Network{net.Network_UDP},
					},
				},
			},
		},
	})
}
