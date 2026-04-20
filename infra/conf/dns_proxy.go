package conf

import (
	"encoding/json"
	"sort"
	"strconv"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/dns"
	"google.golang.org/protobuf/proto"
)

type DNSQueryRulesConfig map[string]json.RawMessage

// UnmarshalJSON implements encoding/json.Unmarshaler.UnmarshalJSON.
func (c *DNSQueryRulesConfig) UnmarshalJSON(data []byte) error {
	m := make(map[string]json.RawMessage)
	if err := json.Unmarshal(data, &m); err != nil {
		return errors.New("invalid dns query rules").Base(err)
	}
	*c = m
	return nil
}

func (c DNSQueryRulesConfig) Build() ([]*dns.Config_QueryRule, error) {
	if len(c) == 0 {
		return nil, nil
	}

	keys := make([]string, 0, len(c))
	for key := range c {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var rules [256]*dns.Config_QueryRule
	for _, key := range keys {
		var qtypes PortList
		if err := qtypes.UnmarshalJSON([]byte(strconv.Quote(key))); err != nil {
			return nil, errors.New("failed to parse dns query rule qtype: ", key).Base(err)
		}

		domains, err := parseQueryDomains(c[key], key)
		if err != nil {
			return nil, err
		}

		for _, r := range qtypes.Range {
			if r.To > 255 {
				return nil, errors.New("dns query rule qtype out of range: ", r.String())
			}
			for qtype := r.From; qtype <= r.To; qtype++ {
				if rules[qtype] == nil {
					rules[qtype] = &dns.Config_QueryRule{Qtype: int32(qtype)}
				}
				rules[qtype].Domain = appendUniqueDomains(rules[qtype].Domain, domains)
			}
		}
	}

	out := make([]*dns.Config_QueryRule, 0)
	for _, rule := range rules {
		if rule != nil {
			out = append(out, rule)
		}
	}
	return out, nil
}

func parseQueryDomains(data json.RawMessage, key string) ([]*geodata.DomainRule, error) {
	var domains *StringList
	if err := json.Unmarshal(data, &domains); err != nil {
		return nil, errors.New("failed to parse dns query rule domains for qtype: ", key).Base(err)
	}
	if domains == nil {
		return nil, nil
	}
	return geodata.ParseDomainRules(*domains, geodata.Domain_Substr)
}

func appendUniqueDomains(dst, src []*geodata.DomainRule) []*geodata.DomainRule {
	for _, rule := range src {
		dup := false
		for _, r := range dst {
			if proto.Equal(r, rule) {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, rule)
		}
	}
	return dst
}

type DNSOutboundConfig struct {
	Network     Network              `json:"network"`
	Address     *Address             `json:"address"`
	Port        uint16               `json:"port"`
	UserLevel   uint32               `json:"userLevel"`
	BlockMethod string               `json:"blockMethod"`
	Blacklist   *DNSQueryRulesConfig `json:"blacklist"`
	Whitelist   *DNSQueryRulesConfig `json:"whitelist"`
	NonIPQuery  *string              `json:"nonIPQuery"` // todo: remove legacy
	BlockTypes  *[]int32             `json:"blockTypes"` // todo: remove legacy
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
		if c.BlockMethod != "" || c.Blacklist != nil || c.Whitelist != nil {
			return nil, errors.New(`legacy "nonIPQuery" and "blockTypes" cannot be mixed with "blockMethod", "blacklist", or "whitelist"`)
		}
		block, reject, rules, err := c.buildLegacyDNSPolicy()
		if err != nil {
			return nil, err
		}
		config.BlockMatched = block
		config.RejectBlocked = reject
		config.QueryRule = rules
		return config, nil
	}

	block, rules, err := c.buildDNSQueryPolicy()
	if err != nil {
		return nil, err
	}
	config.BlockMatched = block
	config.QueryRule = rules

	switch c.BlockMethod {
	case "drop":
		config.RejectBlocked = false
	case "", "reject":
		config.RejectBlocked = true
	default:
		return nil, errors.New(`unknown "blockMethod": `, c.BlockMethod)
	}

	return config, nil
}

func (c *DNSOutboundConfig) buildDNSQueryPolicy() (bool, []*dns.Config_QueryRule, error) {
	switch {
	case c.Blacklist != nil && c.Whitelist != nil:
		return false, nil, errors.New(`"blacklist" and "whitelist" are mutually exclusive`)
	case c.Whitelist != nil:
		rules, err := c.Whitelist.Build()
		return false, rules, err
	case c.Blacklist != nil:
		rules, err := c.Blacklist.Build()
		return true, rules, err
	default:
		return true, nil, nil // default: blacklist mode
	}
}

// todo: remove legacy
func (c *DNSOutboundConfig) buildLegacyDNSPolicy() (bool, bool, []*dns.Config_QueryRule, error) {
	mode := "reject"
	if c.NonIPQuery != nil && *c.NonIPQuery != "" {
		mode = *c.NonIPQuery
	}

	switch mode {
	case "reject", "drop", "skip":
	default:
		return false, false, nil, errors.New(`unknown "nonIPQuery": `, mode)
	}

	var blocked [256]bool
	if c.BlockTypes != nil {
		for _, qtype := range *c.BlockTypes {
			if qtype < 0 || qtype > 255 {
				return false, false, nil, errors.New("legacy blockTypes qtype out of range: ", qtype)
			}
			blocked[qtype] = true
		}
	}

	var rules []*dns.Config_QueryRule
	block := mode == "skip"
	if block {
		for qtype, hit := range blocked {
			if hit {
				rules = append(rules, &dns.Config_QueryRule{Qtype: int32(qtype)})
			}
		}
	} else {
		for _, qtype := range [...]int{1, 28} {
			if !blocked[qtype] {
				rules = append(rules, &dns.Config_QueryRule{Qtype: int32(qtype)})
			}
		}
	}

	return block, mode == "reject", rules, nil
}
