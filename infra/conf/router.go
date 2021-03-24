package conf

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/matcher/conf"
	"github.com/xtls/xray-core/common/matcher/geoip"
	"github.com/xtls/xray-core/common/matcher/geosite"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform/filesystem"
)

type RouterRulesConfig struct {
	RuleList       []json.RawMessage `json:"rules"`
	DomainStrategy string            `json:"domainStrategy"`
}

type BalancingRule struct {
	Tag       string     `json:"tag"`
	Selectors StringList `json:"selector"`
}

func (r *BalancingRule) Build() (*router.BalancingRule, error) {
	if r.Tag == "" {
		return nil, newError("empty balancer tag")
	}
	if len(r.Selectors) == 0 {
		return nil, newError("empty selector list")
	}

	return &router.BalancingRule{
		Tag:              r.Tag,
		OutboundSelector: []string(r.Selectors),
	}, nil
}

type RouterConfig struct {
	Settings       *RouterRulesConfig `json:"settings"` // Deprecated
	RuleList       []json.RawMessage  `json:"rules"`
	DomainStrategy *string            `json:"domainStrategy"`
	Balancers      []*BalancingRule   `json:"balancers"`
}

func (c *RouterConfig) getDomainStrategy() router.Config_DomainStrategy {
	ds := ""
	if c.DomainStrategy != nil {
		ds = *c.DomainStrategy
	} else if c.Settings != nil {
		ds = c.Settings.DomainStrategy
	}

	switch strings.ToLower(ds) {
	case "alwaysip":
		return router.Config_UseIp
	case "ipifnonmatch":
		return router.Config_IpIfNonMatch
	case "ipondemand":
		return router.Config_IpOnDemand
	default:
		return router.Config_AsIs
	}
}

func (c *RouterConfig) Build() (*router.Config, error) {
	config := new(router.Config)
	config.DomainStrategy = c.getDomainStrategy()

	var rawRuleList []json.RawMessage
	if c != nil {
		rawRuleList = c.RuleList
		if c.Settings != nil {
			c.RuleList = append(c.RuleList, c.Settings.RuleList...)
			rawRuleList = c.RuleList
		}
	}

	for _, rawRule := range rawRuleList {
		rule, err := ParseRule(rawRule)
		if err != nil {
			return nil, err
		}
		config.Rule = append(config.Rule, rule)
	}
	for _, rawBalancer := range c.Balancers {
		balancer, err := rawBalancer.Build()
		if err != nil {
			return nil, err
		}
		config.BalancingRule = append(config.BalancingRule, balancer)
	}
	return config, nil
}

type RouterRule struct {
	Type        string `json:"type"`
	OutboundTag string `json:"outboundTag"`
	BalancerTag string `json:"balancerTag"`
}

func ParseIP(s string) (*geoip.CIDR, error) {
	var addr, mask string
	i := strings.Index(s, "/")
	if i < 0 {
		addr = s
	} else {
		addr = s[:i]
		mask = s[i+1:]
	}
	ip := net.ParseAddress(addr)
	switch ip.Family() {
	case net.AddressFamilyIPv4:
		bits := uint32(32)
		if len(mask) > 0 {
			bits64, err := strconv.ParseUint(mask, 10, 32)
			if err != nil {
				return nil, newError("invalid network mask for router: ", mask).Base(err)
			}
			bits = uint32(bits64)
		}
		if bits > 32 {
			return nil, newError("invalid network mask for router: ", bits)
		}
		return &geoip.CIDR{
			Ip:     []byte(ip.IP()),
			Prefix: bits,
		}, nil
	case net.AddressFamilyIPv6:
		bits := uint32(128)
		if len(mask) > 0 {
			bits64, err := strconv.ParseUint(mask, 10, 32)
			if err != nil {
				return nil, newError("invalid network mask for router: ", mask).Base(err)
			}
			bits = uint32(bits64)
		}
		if bits > 128 {
			return nil, newError("invalid network mask for router: ", bits)
		}
		return &geoip.CIDR{
			Ip:     ip.IP(),
			Prefix: bits,
		}, nil
	default:
		return nil, newError("unsupported address for router: ", s)
	}
}

var (
	FileCache = make(map[string][]byte)
	IPCache   = make(map[string]*geoip.GeoIP)
)

func loadFile(file string) ([]byte, error) {
	if FileCache[file] == nil {
		bs, err := filesystem.ReadAsset(file)
		if err != nil {
			return nil, newError("failed to open file: ", file).Base(err)
		}
		if len(bs) == 0 {
			return nil, newError("empty file: ", file)
		}
		// Do not cache file, may save RAM when there
		// are many files, but consume CPU each time.
		return bs, nil
		FileCache[file] = bs
	}
	return FileCache[file], nil
}

func toCidrList(ips StringList) ([]*geoip.GeoIP, error) {
	var geoipList []*geoip.GeoIP
	var customCidrs []*geoip.CIDR

	for _, ip := range ips {
		if strings.HasPrefix(ip, "geoip:") {
			country := ip[6:]
			geoipc, err := geoip.LoadGeoIP(strings.ToUpper(country))
			if err != nil {
				return nil, newError("failed to load GeoIP: ", country).Base(err)
			}

			geoipList = append(geoipList, &geoip.GeoIP{
				CountryCode: strings.ToUpper(country),
				Cidr:        geoipc,
			})
			continue
		}
		var isExtDatFile = 0
		{
			const prefix = "ext:"
			if strings.HasPrefix(ip, prefix) {
				isExtDatFile = len(prefix)
			}
			const prefixQualified = "ext-ip:"
			if strings.HasPrefix(ip, prefixQualified) {
				isExtDatFile = len(prefixQualified)
			}
		}
		if isExtDatFile != 0 {
			kv := strings.Split(ip[isExtDatFile:], ":")
			if len(kv) != 2 {
				return nil, newError("invalid external resource: ", ip)
			}

			filename := kv[0]
			country := kv[1]
			geoipc, err := geoip.LoadIPFile(filename, strings.ToUpper(country))
			if err != nil {
				return nil, newError("failed to load IPs: ", country, " from ", filename).Base(err)
			}

			geoipList = append(geoipList, &geoip.GeoIP{
				CountryCode: strings.ToUpper(filename + "_" + country),
				Cidr:        geoipc,
			})

			continue
		}

		ipRule, err := ParseIP(ip)
		if err != nil {
			return nil, newError("invalid IP: ", ip).Base(err)
		}
		customCidrs = append(customCidrs, ipRule)
	}

	if len(customCidrs) > 0 {
		geoipList = append(geoipList, &geoip.GeoIP{
			Cidr: customCidrs,
		})
	}

	return geoipList, nil
}

func parseFieldRule(msg json.RawMessage) (*router.RoutingRule, error) {
	type RawFieldRule struct {
		RouterRule
		Domain     *StringList  `json:"domain"`
		Domains    *StringList  `json:"domains"`
		IP         *StringList  `json:"ip"`
		Port       *PortList    `json:"port"`
		Network    *NetworkList `json:"network"`
		SourceIP   *StringList  `json:"source"`
		SourcePort *PortList    `json:"sourcePort"`
		User       *StringList  `json:"user"`
		InboundTag *StringList  `json:"inboundTag"`
		Protocols  *StringList  `json:"protocol"`
		Attributes string       `json:"attrs"`
	}
	rawFieldRule := new(RawFieldRule)
	err := json.Unmarshal(msg, rawFieldRule)
	if err != nil {
		return nil, err
	}

	rule := new(router.RoutingRule)
	switch {
	case len(rawFieldRule.OutboundTag) > 0:
		rule.TargetTag = &router.RoutingRule_Tag{
			Tag: rawFieldRule.OutboundTag,
		}
	case len(rawFieldRule.BalancerTag) > 0:
		rule.TargetTag = &router.RoutingRule_BalancingTag{
			BalancingTag: rawFieldRule.BalancerTag,
		}
	default:
		return nil, newError("neither outboundTag nor balancerTag is specified in routing rule")
	}

	if rawFieldRule.Domain != nil {
		for _, domain := range *rawFieldRule.Domain {
			rules, err := conf.ParaseDomainRule(domain)
			if err != nil {
				return nil, newError("failed to parse domain rule: ", domain).Base(err)
			}
			rule.Domain = append(rule.Domain, rules...)
		}
	}

	if rawFieldRule.Domains != nil {
		for _, domain := range *rawFieldRule.Domains {
			rules, err := conf.ParaseDomainRule(domain)
			if err != nil {
				return nil, newError("failed to parse domain rule: ", domain).Base(err)
			}
			rule.Domain = append(rule.Domain, rules...)
		}
	}

	if rawFieldRule.IP != nil {
		geoipList, err := toCidrList(*rawFieldRule.IP)
		if err != nil {
			return nil, err
		}
		rule.Geoip = geoipList
	}

	if rawFieldRule.Port != nil {
		rule.PortList = rawFieldRule.Port.Build()
	}

	if rawFieldRule.Network != nil {
		rule.Networks = rawFieldRule.Network.Build()
	}

	if rawFieldRule.SourceIP != nil {
		geoipList, err := toCidrList(*rawFieldRule.SourceIP)
		if err != nil {
			return nil, err
		}
		rule.SourceGeoip = geoipList
	}

	if rawFieldRule.SourcePort != nil {
		rule.SourcePortList = rawFieldRule.SourcePort.Build()
	}

	if rawFieldRule.User != nil {
		for _, s := range *rawFieldRule.User {
			rule.UserEmail = append(rule.UserEmail, s)
		}
	}

	if rawFieldRule.InboundTag != nil {
		for _, s := range *rawFieldRule.InboundTag {
			rule.InboundTag = append(rule.InboundTag, s)
		}
	}

	if rawFieldRule.Protocols != nil {
		for _, s := range *rawFieldRule.Protocols {
			rule.Protocol = append(rule.Protocol, s)
		}
	}

	if len(rawFieldRule.Attributes) > 0 {
		rule.Attributes = rawFieldRule.Attributes
	}

	return rule, nil
}

func ParseRule(msg json.RawMessage) (*router.RoutingRule, error) {
	rawRule := new(RouterRule)
	err := json.Unmarshal(msg, rawRule)
	if err != nil {
		return nil, newError("invalid router rule").Base(err)
	}
	if rawRule.Type == "field" {
		fieldrule, err := parseFieldRule(msg)
		if err != nil {
			return nil, newError("invalid field rule").Base(err)
		}
		return fieldrule, nil
	}
	if rawRule.Type == "chinaip" {
		chinaiprule, err := parseChinaIPRule(msg)
		if err != nil {
			return nil, newError("invalid chinaip rule").Base(err)
		}
		return chinaiprule, nil
	}
	if rawRule.Type == "chinasites" {
		chinasitesrule, err := parseChinaSitesRule(msg)
		if err != nil {
			return nil, newError("invalid chinasites rule").Base(err)
		}
		return chinasitesrule, nil
	}
	return nil, newError("unknown router rule type: ", rawRule.Type)
}

func parseChinaIPRule(data []byte) (*router.RoutingRule, error) {
	rawRule := new(RouterRule)
	err := json.Unmarshal(data, rawRule)
	if err != nil {
		return nil, newError("invalid router rule").Base(err)
	}
	chinaIPs, err := geoip.LoadGeoIP("CN")
	if err != nil {
		return nil, newError("failed to load geoip:cn").Base(err)
	}
	return &router.RoutingRule{
		TargetTag: &router.RoutingRule_Tag{
			Tag: rawRule.OutboundTag,
		},
		Cidr: chinaIPs,
	}, nil
}

func parseChinaSitesRule(data []byte) (*router.RoutingRule, error) {
	rawRule := new(RouterRule)
	err := json.Unmarshal(data, rawRule)
	if err != nil {
		return nil, newError("invalid router rule").Base(err).AtError()
	}
	domains, err := geosite.LoadGeositeWithAttr("geosite.dat", "CN")
	if err != nil {
		return nil, newError("failed to load geosite:cn.").Base(err)
	}
	return &router.RoutingRule{
		TargetTag: &router.RoutingRule_Tag{
			Tag: rawRule.OutboundTag,
		},
		Domain: domains,
	}, nil
}
