package conf

import (
	"encoding/json"
	"runtime"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"github.com/xtls/xray-core/common/serial"
	"google.golang.org/protobuf/proto"
)

// StrategyConfig represents a strategy config
type StrategyConfig struct {
	Type     string           `json:"type"`
	Settings *json.RawMessage `json:"settings"`
}

type BalancingRule struct {
	Tag         string         `json:"tag"`
	Selectors   StringList     `json:"selector"`
	Strategy    StrategyConfig `json:"strategy"`
	FallbackTag string         `json:"fallbackTag"`
}

// Build builds the balancing rule
func (r *BalancingRule) Build() (*router.BalancingRule, error) {
	if r.Tag == "" {
		return nil, errors.New("empty balancer tag")
	}
	if len(r.Selectors) == 0 {
		return nil, errors.New("empty selector list")
	}

	r.Strategy.Type = strings.ToLower(r.Strategy.Type)
	switch r.Strategy.Type {
	case "":
		r.Strategy.Type = strategyRandom
	case strategyRandom, strategyLeastLoad, strategyLeastPing, strategyRoundRobin:
	default:
		return nil, errors.New("unknown balancing strategy: " + r.Strategy.Type)
	}

	settings := []byte("{}")
	if r.Strategy.Settings != nil {
		settings = ([]byte)(*r.Strategy.Settings)
	}
	rawConfig, err := strategyConfigLoader.LoadWithID(settings, r.Strategy.Type)
	if err != nil {
		return nil, errors.New("failed to parse to strategy config.").Base(err)
	}
	var ts proto.Message
	if builder, ok := rawConfig.(Buildable); ok {
		ts, err = builder.Build()
		if err != nil {
			return nil, err
		}
	}

	return &router.BalancingRule{
		Strategy:         r.Strategy.Type,
		StrategySettings: serial.ToTypedMessage(ts),
		FallbackTag:      r.FallbackTag,
		OutboundSelector: r.Selectors,
		Tag:              r.Tag,
	}, nil
}

type RouterConfig struct {
	RuleList       []json.RawMessage `json:"rules"`
	DomainStrategy *string           `json:"domainStrategy"`
	Balancers      []*BalancingRule  `json:"balancers"`
}

func (c *RouterConfig) getDomainStrategy() router.Config_DomainStrategy {
	ds := ""
	if c.DomainStrategy != nil {
		ds = *c.DomainStrategy
	}

	switch strings.ToLower(ds) {
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
	RuleTag     string `json:"ruleTag"`
	OutboundTag string `json:"outboundTag"`
	BalancerTag string `json:"balancerTag"`
}

func ParseIP(s string) (*router.CIDR, error) {
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
				return nil, errors.New("invalid network mask for router: ", mask).Base(err)
			}
			bits = uint32(bits64)
		}
		if bits > 32 {
			return nil, errors.New("invalid network mask for router: ", bits)
		}
		return &router.CIDR{
			Ip:     []byte(ip.IP()),
			Prefix: bits,
		}, nil
	case net.AddressFamilyIPv6:
		bits := uint32(128)
		if len(mask) > 0 {
			bits64, err := strconv.ParseUint(mask, 10, 32)
			if err != nil {
				return nil, errors.New("invalid network mask for router: ", mask).Base(err)
			}
			bits = uint32(bits64)
		}
		if bits > 128 {
			return nil, errors.New("invalid network mask for router: ", bits)
		}
		return &router.CIDR{
			Ip:     []byte(ip.IP()),
			Prefix: bits,
		}, nil
	default:
		return nil, errors.New("unsupported address for router: ", s)
	}
}

func loadGeoIP(code string) ([]*router.CIDR, error) {
	return loadIP("geoip.dat", code)
}

var (
	FileCache = make(map[string][]byte)
	IPCache   = make(map[string]*router.GeoIP)
	SiteCache = make(map[string]*router.GeoSite)
)

func loadFile(file string) ([]byte, error) {
	if FileCache[file] == nil {
		bs, err := filesystem.ReadAsset(file)
		if err != nil {
			return nil, errors.New("failed to open file: ", file).Base(err)
		}
		if len(bs) == 0 {
			return nil, errors.New("empty file: ", file)
		}
		// Do not cache file, may save RAM when there
		// are many files, but consume CPU each time.
		return bs, nil
		FileCache[file] = bs
	}
	return FileCache[file], nil
}

func loadIP(file, code string) ([]*router.CIDR, error) {
	index := file + ":" + code
	if IPCache[index] == nil {
		var geoip router.GeoIP

		if runtime.GOOS != "windows" && runtime.GOOS != "wasm" {
			// dont pass code becuase we have country code in top level router.GeoIP
			geoip = router.GeoIP{Cidr: []*router.CIDR{}}
		} else {
			bs, err := loadFile(file)
			if err != nil {
				return nil, errors.New("failed to load file: ", file).Base(err)
			}
			bs = filesystem.Find(bs, []byte(code))
			if bs == nil {
				return nil, errors.New("code not found in ", file, ": ", code)
			}
			if err := proto.Unmarshal(bs, &geoip); err != nil {
				return nil, errors.New("error unmarshal IP in ", file, ": ", code).Base(err)
			}
		}
		defer runtime.GC()     // or debug.FreeOSMemory()
		return geoip.Cidr, nil // do not cache geoip
		IPCache[index] = &geoip
	}
	return IPCache[index].Cidr, nil
}

func loadSite(file, code string) ([]*router.Domain, error) {
	index := file + ":" + code
	if SiteCache[index] == nil {
		var geosite router.GeoSite

		if runtime.GOOS != "windows" && runtime.GOOS != "wasm" {
			// pass file:code so can build optimized matcher later
			domain := router.Domain{Value: file + "_" + code}
			geosite = router.GeoSite{Domain: []*router.Domain{&domain}}

		} else {

			bs, err := loadFile(file)
			if err != nil {
				return nil, errors.New("failed to load file: ", file).Base(err)
			}
			bs = filesystem.Find(bs, []byte(code))
			if bs == nil {
				return nil, errors.New("list not found in ", file, ": ", code)
			}
			if err := proto.Unmarshal(bs, &geosite); err != nil {
				return nil, errors.New("error unmarshal Site in ", file, ": ", code).Base(err)
			}
		}

		defer runtime.GC()         // or debug.FreeOSMemory()
		return geosite.Domain, nil // do not cache geosite
		SiteCache[index] = &geosite
	}
	return SiteCache[index].Domain, nil
}

func loadGeositeWithAttr(file string, siteWithAttr string) ([]*router.Domain, error) {
	parts := strings.Split(siteWithAttr, "@")
	if len(parts) == 0 {
		return nil, errors.New("empty site")
	}
	country := strings.ToUpper(parts[0])
	attrs := router.ParseAttrs(parts[1:])
	domains, err := loadSite(file, country)
	if err != nil {
		return nil, err
	}

	if attrs.IsEmpty() {
		return domains, nil
	}

	if runtime.GOOS != "windows" && runtime.GOOS != "wasm" {
		domains[0].Value = domains[0].Value + "_" + strings.Join(parts[1:], ",")
		return domains, nil
	}

	filteredDomains := make([]*router.Domain, 0, len(domains))
	for _, domain := range domains {
		if attrs.Match(domain) {
			filteredDomains = append(filteredDomains, domain)
		}
	}

	return filteredDomains, nil
}

func ParseDomainRule(domain string) ([]*router.Domain, error) {
	if strings.HasPrefix(domain, "geosite:") {
		country := strings.ToUpper(domain[8:])
		domains, err := loadGeositeWithAttr("geosite.dat", country)
		if err != nil {
			return nil, errors.New("failed to load geosite: ", country).Base(err)
		}
		return domains, nil
	}
	isExtDatFile := 0
	{
		const prefix = "ext:"
		if strings.HasPrefix(domain, prefix) {
			isExtDatFile = len(prefix)
		}
		const prefixQualified = "ext-domain:"
		if strings.HasPrefix(domain, prefixQualified) {
			isExtDatFile = len(prefixQualified)
		}
	}
	if isExtDatFile != 0 {
		kv := strings.Split(domain[isExtDatFile:], ":")
		if len(kv) != 2 {
			return nil, errors.New("invalid external resource: ", domain)
		}
		filename := kv[0]
		country := kv[1]
		domains, err := loadGeositeWithAttr(filename, country)
		if err != nil {
			return nil, errors.New("failed to load external sites: ", country, " from ", filename).Base(err)
		}
		return domains, nil
	}

	domainRule := new(router.Domain)
	switch {
	case strings.HasPrefix(domain, "regexp:"):
		domainRule.Type = router.Domain_Regex
		domainRule.Value = domain[7:]

	case strings.HasPrefix(domain, "domain:"):
		domainRule.Type = router.Domain_Domain
		domainRule.Value = domain[7:]

	case strings.HasPrefix(domain, "full:"):
		domainRule.Type = router.Domain_Full
		domainRule.Value = domain[5:]

	case strings.HasPrefix(domain, "keyword:"):
		domainRule.Type = router.Domain_Plain
		domainRule.Value = domain[8:]

	case strings.HasPrefix(domain, "dotless:"):
		domainRule.Type = router.Domain_Regex
		switch substr := domain[8:]; {
		case substr == "":
			domainRule.Value = "^[^.]*$"
		case !strings.Contains(substr, "."):
			domainRule.Value = "^[^.]*" + substr + "[^.]*$"
		default:
			return nil, errors.New("substr in dotless rule should not contain a dot: ", substr)
		}

	default:
		domainRule.Type = router.Domain_Plain
		domainRule.Value = domain
	}
	return []*router.Domain{domainRule}, nil
}

func ToCidrList(ips StringList) ([]*router.GeoIP, error) {
	var geoipList []*router.GeoIP
	var customCidrs []*router.CIDR

	for _, ip := range ips {
		if strings.HasPrefix(ip, "geoip:") {
			country := ip[6:]
			isReverseMatch := false
			if strings.HasPrefix(ip, "geoip:!") {
				country = ip[7:]
				isReverseMatch = true
			}
			if len(country) == 0 {
				return nil, errors.New("empty country name in rule")
			}
			geoip, err := loadGeoIP(strings.ToUpper(country))
			if err != nil {
				return nil, errors.New("failed to load GeoIP: ", country).Base(err)
			}

			geoipList = append(geoipList, &router.GeoIP{
				CountryCode:  strings.ToUpper(country),
				Cidr:         geoip,
				ReverseMatch: isReverseMatch,
			})
			continue
		}
		isExtDatFile := 0
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
				return nil, errors.New("invalid external resource: ", ip)
			}

			filename := kv[0]
			country := kv[1]
			if len(filename) == 0 || len(country) == 0 {
				return nil, errors.New("empty filename or empty country in rule")
			}

			isReverseMatch := false
			if strings.HasPrefix(country, "!") {
				country = country[1:]
				isReverseMatch = true
			}
			geoip, err := loadIP(filename, strings.ToUpper(country))
			if err != nil {
				return nil, errors.New("failed to load IPs: ", country, " from ", filename).Base(err)
			}

			geoipList = append(geoipList, &router.GeoIP{
				CountryCode:  strings.ToUpper(filename + "_" + country),
				Cidr:         geoip,
				ReverseMatch: isReverseMatch,
			})

			continue
		}

		ipRule, err := ParseIP(ip)
		if err != nil {
			return nil, errors.New("invalid IP: ", ip).Base(err)
		}
		customCidrs = append(customCidrs, ipRule)
	}

	if len(customCidrs) > 0 {
		geoipList = append(geoipList, &router.GeoIP{
			Cidr: customCidrs,
		})
	}

	return geoipList, nil
}

func parseFieldRule(msg json.RawMessage) (*router.RoutingRule, error) {
	type RawFieldRule struct {
		RouterRule
		Domain     *StringList       `json:"domain"`
		Domains    *StringList       `json:"domains"`
		IP         *StringList       `json:"ip"`
		Port       *PortList         `json:"port"`
		Network    *NetworkList      `json:"network"`
		SourceIP   *StringList       `json:"sourceIP"`
		Source     *StringList       `json:"source"`
		SourcePort *PortList         `json:"sourcePort"`
		User       *StringList       `json:"user"`
		VlessRoute *PortList         `json:"vlessRoute"`
		InboundTag *StringList       `json:"inboundTag"`
		Protocols  *StringList       `json:"protocol"`
		Attributes map[string]string `json:"attrs"`
		LocalIP    *StringList       `json:"localIP"`
		LocalPort  *PortList         `json:"localPort"`
		Process    *StringList       `json:"process"`
	}
	rawFieldRule := new(RawFieldRule)
	err := json.Unmarshal(msg, rawFieldRule)
	if err != nil {
		return nil, err
	}

	rule := new(router.RoutingRule)
	rule.RuleTag = rawFieldRule.RuleTag
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
		return nil, errors.New("neither outboundTag nor balancerTag is specified in routing rule")
	}

	if rawFieldRule.Domain != nil {
		for _, domain := range *rawFieldRule.Domain {
			rules, err := ParseDomainRule(domain)
			if err != nil {
				return nil, errors.New("failed to parse domain rule: ", domain).Base(err)
			}
			rule.Domain = append(rule.Domain, rules...)
		}
	}

	if rawFieldRule.Domains != nil {
		for _, domain := range *rawFieldRule.Domains {
			rules, err := ParseDomainRule(domain)
			if err != nil {
				return nil, errors.New("failed to parse domain rule: ", domain).Base(err)
			}
			rule.Domain = append(rule.Domain, rules...)
		}
	}

	if rawFieldRule.IP != nil {
		geoipList, err := ToCidrList(*rawFieldRule.IP)
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

	if rawFieldRule.SourceIP == nil {
		rawFieldRule.SourceIP = rawFieldRule.Source
	}

	if rawFieldRule.SourceIP != nil {
		geoipList, err := ToCidrList(*rawFieldRule.SourceIP)
		if err != nil {
			return nil, err
		}
		rule.SourceGeoip = geoipList
	}

	if rawFieldRule.SourcePort != nil {
		rule.SourcePortList = rawFieldRule.SourcePort.Build()
	}

	if rawFieldRule.LocalIP != nil {
		geoipList, err := ToCidrList(*rawFieldRule.LocalIP)
		if err != nil {
			return nil, err
		}
		rule.LocalGeoip = geoipList
	}

	if rawFieldRule.LocalPort != nil {
		rule.LocalPortList = rawFieldRule.LocalPort.Build()
	}

	if rawFieldRule.User != nil {
		for _, s := range *rawFieldRule.User {
			rule.UserEmail = append(rule.UserEmail, s)
		}
	}

	if rawFieldRule.VlessRoute != nil {
		rule.VlessRouteList = rawFieldRule.VlessRoute.Build()
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

	if rawFieldRule.Process != nil && len(*rawFieldRule.Process) > 0 {
		rule.Process = *rawFieldRule.Process
	}

	return rule, nil
}

func ParseRule(msg json.RawMessage) (*router.RoutingRule, error) {
	rawRule := new(RouterRule)
	err := json.Unmarshal(msg, rawRule)
	if err != nil {
		return nil, errors.New("invalid router rule").Base(err)
	}

	fieldrule, err := parseFieldRule(msg)
	if err != nil {
		return nil, errors.New("invalid field rule").Base(err)
	}
	return fieldrule, nil
}
