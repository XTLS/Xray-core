package conf_test

import (
	"testing"

	"github.com/xtls/xray-core/common/log"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/freedom"
)

func TestHTTPResponseJSON(t *testing.T) {
	creator := func() Buildable {
		return new(BlackholeConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"response": {
					"type": "http"
				}
			}`,
			Parser: loadJSON(creator),
			Output: &freedom.Config{
				Firewall: []*freedom.FirewallConfig{{
					Action:   freedom.RuleAction_Block,
					Delay:    &freedom.Range{},
					LogLevel: log.Severity_Unknown.Enum(),
					Reply:    &freedom.Reply{Type: "http"},
				}},
			},
		},
		{
			Input:  `{}`,
			Parser: loadJSON(creator),
			Output: &freedom.Config{
				Firewall: []*freedom.FirewallConfig{{
					Action:   freedom.RuleAction_Block,
					Delay:    &freedom.Range{},
					LogLevel: log.Severity_Unknown.Enum(),
				}},
			},
		},
	})
}

func TestCustomResponseJSON(t *testing.T) {
	creator := func() Buildable {
		return new(BlackholeConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"response": {
					"type": "custom",
					"customResponseData": "Y3VzdG9tIHJlc3BvbnNl"
				}
			}`,
			Parser: loadJSON(creator),
			Output: &freedom.Config{
				Firewall: []*freedom.FirewallConfig{{
					Action:   freedom.RuleAction_Block,
					Delay:    &freedom.Range{},
					LogLevel: log.Severity_Unknown.Enum(),
					Reply: &freedom.Reply{
						Type:               "custom",
						CustomResponseData: []byte("custom response"),
					},
				}},
			},
		},
	})
}
