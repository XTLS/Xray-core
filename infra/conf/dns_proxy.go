package conf

import (
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/dns"
	"google.golang.org/protobuf/proto"
)

type DNSOutboundRuleConfig struct {
	Action string      `json:"action"`
	QType  *PortList   `json:"qtype"`
	Domain *StringList `json:"domain"`
}

func (c *DNSOutboundRuleConfig) Build() (*dns.DNSRuleConfig, error) {
	rule := &dns.DNSRuleConfig{}

	switch strings.ToLower(c.Action) {
	case "direct":
		rule.Action = dns.RuleAction_Direct
	case "drop":
		rule.Action = dns.RuleAction_Drop
	case "reject":
		rule.Action = dns.RuleAction_Reject
	case "hijack":
		rule.Action = dns.RuleAction_Hijack
	default:
		return nil, errors.New("unknown action: ", c.Action)
	}

	if c.QType != nil {
		for _, r := range c.QType.Range {
			if r.From > r.To {
				return nil, errors.New("invalid qtype range: ", r.String())
			}
			if r.To > 65535 {
				return nil, errors.New("dns rule qtype out of range: ", r.String())
			}
			for qtype := r.From; qtype <= r.To; qtype++ {
				rule.Qtype = append(rule.Qtype, int32(qtype))
			}
		}
	}

	if c.Domain != nil {
		rules, err := geodata.ParseDomainRules(*c.Domain, geodata.Domain_Substr)
		if err != nil {
			return nil, err
		}
		rule.Domain = rules
	}

	return rule, nil
}

type DNSOutboundConfig struct {
	Network    Network                  `json:"network"`
	Address    *Address                 `json:"address"`
	Port       uint16                   `json:"port"`
	UserLevel  uint32                   `json:"userLevel"`
	Rules      []*DNSOutboundRuleConfig `json:"rules"`
	NonIPQuery *string                  `json:"nonIPQuery"` // todo: remove legacy
	BlockTypes *[]int32                 `json:"blockTypes"` // todo: remove legacy
}

func (c *DNSOutboundConfig) Build() (proto.Message, error) {
	config := &dns.Config{
		Server: &net.Endpoint{
			Network: c.Network.Build(),
			Port:    uint32(c.Port),
		},
		UserLevel: c.UserLevel,
	}
	if c.Address != nil {
		config.Server.Address = c.Address.Build()
	}

	// todo: remove legacy
	if c.NonIPQuery != nil || c.BlockTypes != nil {
		if c.Rules != nil {
			return nil, errors.New("legacy nonIPQuery and blockTypes cannot be mixed with rules")
		}
		errors.PrintDeprecatedFeatureWarning(`"nonIPQuery" and "blockTypes"`, `"rules"`)
		rules, err := c.buildLegacyDNSPolicy()
		if err != nil {
			return nil, err
		}
		config.Rule = rules
		return config, nil
	}

	for _, r := range c.Rules {
		rule, err := r.Build()
		if err != nil {
			return nil, err
		}
		config.Rule = append(config.Rule, rule)
	}

	return config, nil
}

// todo: remove legacy
func (c *DNSOutboundConfig) buildLegacyDNSPolicy() ([]*dns.DNSRuleConfig, error) {
	rules := make([]*dns.DNSRuleConfig, 0, 3)

	mode := "reject"
	if c.NonIPQuery != nil && *c.NonIPQuery != "" {
		mode = *c.NonIPQuery
	}
	switch mode {
	case "", "reject", "drop", "skip":
	default:
		return nil, errors.New("unknown nonIPQuery: ", mode)
	}

	if c.BlockTypes != nil && len(*c.BlockTypes) > 0 {
		rule := &dns.DNSRuleConfig{Action: dns.RuleAction_Drop}
		if mode == "reject" {
			rule.Action = dns.RuleAction_Reject
		}
		for _, qtype := range *c.BlockTypes {
			if qtype < 0 || qtype > 65535 {
				return nil, errors.New("legacy blockTypes qtype out of range: ", qtype)
			}
			rule.Qtype = append(rule.Qtype, qtype)
		}
		rules = append(rules, rule)
	}

	{
		rule := &dns.DNSRuleConfig{Action: dns.RuleAction_Hijack}
		rule.Qtype = append(rule.Qtype, 1)
		rule.Qtype = append(rule.Qtype, 28)
		rules = append(rules, rule)
	}

	{
		rule := &dns.DNSRuleConfig{Action: dns.RuleAction_Reject}
		if mode == "reject" {
			rule.Action = dns.RuleAction_Reject
		} else if mode == "drop" {
			rule.Action = dns.RuleAction_Drop
		} else if mode == "skip" {
			rule.Action = dns.RuleAction_Direct
		}
		rules = append(rules, rule)
	}

	return rules, nil
}
