package geodata

import (
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

const (
	DefaultGeoIPDat   = "geoip.dat"
	DefaultGeoSiteDat = "geosite.dat"
)

func ParseIPRules(rules []string) ([]*IPRule, error) {
	var ipRules []*IPRule

	for i, r := range rules {
		if strings.HasPrefix(r, "geoip:") {
			r = "ext:" + DefaultGeoIPDat + ":" + r[len("geoip:"):]
		}

		prefix := 0
		for _, ext := range [...]string{"ext:", "ext-ip:"} {
			if strings.HasPrefix(r, ext) {
				prefix = len(ext)
				break
			}
		}

		var rule isIPRule_Value
		var err error
		if prefix > 0 {
			rule, err = parseGeoIPRule(r[prefix:])
		} else {
			rule, err = parseCustomIPRule(r)
		}
		if err != nil {
			return nil, errors.New("illegal ip rule: ", rules[i]).Base(err)
		}
		ipRules = append(ipRules, &IPRule{Value: rule})
	}

	return ipRules, nil
}

func parseGeoIPRule(rule string) (*IPRule_Geoip, error) {
	file, code, ok := strings.Cut(rule, ":")
	if !ok {
		return nil, errors.New("syntax error")
	}

	if file == "" {
		return nil, errors.New("empty file")
	}

	reverse := false
	if strings.HasPrefix(code, "!") {
		code = code[1:]
		reverse = true
	}
	if code == "" {
		return nil, errors.New("empty code")
	}
	code = strings.ToUpper(code)

	if err := checkFile(file, code); err != nil {
		return nil, err
	}

	return &IPRule_Geoip{
		Geoip: &GeoIPRule{
			File:         file,
			Code:         code,
			ReverseMatch: reverse,
		},
	}, nil
}

func parseCustomIPRule(rule string) (*IPRule_Custom, error) {
	cidr, err := parseCIDR(rule)
	if err != nil {
		return nil, err
	}
	return &IPRule_Custom{
		Custom: cidr,
	}, nil
}

func parseCIDR(s string) (*CIDR, error) {
	ipStr, prefixStr, _ := strings.Cut(s, "/")

	ipAddr := net.ParseAddress(ipStr)

	var maxPrefix uint32
	switch ipAddr.Family() {
	case net.AddressFamilyIPv4:
		maxPrefix = 32
	case net.AddressFamilyIPv6:
		maxPrefix = 128
	default:
		return nil, errors.New("unsupported address family")
	}

	prefixBits := maxPrefix
	if prefixStr != "" {
		parsedPrefix, err := strconv.ParseUint(prefixStr, 10, 32)
		if err != nil {
			return nil, errors.New("invalid CIDR prefix length: ", prefixStr).Base(err)
		}
		prefixBits = uint32(parsedPrefix)
	}
	if prefixBits > maxPrefix {
		return nil, errors.New("CIDR prefix length ", prefixBits, " exceeds max ", maxPrefix)
	}

	return &CIDR{
		Ip:     []byte(ipAddr.IP()),
		Prefix: prefixBits,
	}, nil
}

func ParseDomainRule(r string, defaultType Domain_Type) (*DomainRule, error) {
	if strings.HasPrefix(r, "geosite:") {
		r = "ext:" + DefaultGeoSiteDat + ":" + r[len("geosite:"):]
	}

	prefix := 0
	for _, ext := range [...]string{"ext:", "ext-domain:"} {
		if strings.HasPrefix(r, ext) {
			prefix = len(ext)
			break
		}
	}

	var rule isDomainRule_Value
	var err error
	if prefix > 0 {
		rule, err = parseGeoSiteRule(r[prefix:])
	} else {
		rule, err = parseCustomDomainRule(r, defaultType)
	}
	if err != nil {
		return nil, errors.New("illegal domain rule: ", r).Base(err)
	}
	return &DomainRule{Value: rule}, nil
}

func ParseDomainRules(rules []string, defaultType Domain_Type) ([]*DomainRule, error) {
	var domainRules []*DomainRule

	for i, r := range rules {
		if strings.HasPrefix(r, "geosite:") {
			r = "ext:" + DefaultGeoSiteDat + ":" + r[len("geosite:"):]
		}

		prefix := 0
		for _, ext := range [...]string{"ext:", "ext-domain:"} {
			if strings.HasPrefix(r, ext) {
				prefix = len(ext)
				break
			}
		}

		var rule isDomainRule_Value
		var err error
		if prefix > 0 {
			rule, err = parseGeoSiteRule(r[prefix:])
		} else {
			rule, err = parseCustomDomainRule(r, defaultType)
		}
		if err != nil {
			return nil, errors.New("illegal domain rule: ", rules[i]).Base(err)
		}
		domainRules = append(domainRules, &DomainRule{Value: rule})
	}

	return domainRules, nil
}

func parseGeoSiteRule(rule string) (*DomainRule_Geosite, error) {
	file, codeWithAttrs, ok := strings.Cut(rule, ":")
	if !ok {
		return nil, errors.New("syntax error")
	}

	if file == "" {
		return nil, errors.New("empty file")
	}

	if strings.HasSuffix(codeWithAttrs, "@") || strings.Contains(codeWithAttrs, "@@") {
		return nil, errors.New("empty attr")
	}
	code, attrs, _ := strings.Cut(codeWithAttrs, "@")

	if code == "" {
		return nil, errors.New("empty code")
	}
	code = strings.ToUpper(code)

	if err := checkFile(file, code); err != nil {
		return nil, err
	}

	return &DomainRule_Geosite{
		Geosite: &GeoSiteRule{
			File:  file,
			Code:  code,
			Attrs: strings.ToLower(attrs),
		},
	}, nil
}

func parseCustomDomainRule(rule string, defaultType Domain_Type) (*DomainRule_Custom, error) {
	domain := new(Domain)

	switch {
	case strings.HasPrefix(rule, "regexp:"):
		domain.Type = Domain_Regex
		domain.Value = rule[7:]

	case strings.HasPrefix(rule, "domain:"):
		domain.Type = Domain_Domain
		domain.Value = rule[7:]

	case strings.HasPrefix(rule, "full:"):
		domain.Type = Domain_Full
		domain.Value = rule[5:]

	case strings.HasPrefix(rule, "keyword:"):
		domain.Type = Domain_Substr
		domain.Value = rule[8:]

	case strings.HasPrefix(rule, "dotless:"):
		domain.Type = Domain_Regex
		switch substr := rule[8:]; {
		case substr == "":
			domain.Value = "^[^.]*$"
		case !strings.Contains(substr, "."):
			domain.Value = "^[^.]*" + substr + "[^.]*$"
		default:
			return nil, errors.New("substr in dotless rule should not contain a dot")
		}

	default:
		domain.Type = defaultType
		domain.Value = rule
	}

	return &DomainRule_Custom{
		Custom: domain,
	}, nil
}
