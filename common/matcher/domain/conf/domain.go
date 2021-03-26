package conf

import (
	"strings"

	dm "github.com/xtls/xray-core/common/matcher/domain"
	"github.com/xtls/xray-core/common/matcher/geosite"
)

func ParseDomainRule(domain string) ([]*dm.Domain, error) {
	if strings.HasPrefix(domain, "geosite:") {
		country := strings.ToUpper(domain[8:])
		domains, err := geosite.LoadGeositeWithAttr("geosite.dat", country)
		if err != nil {
			return nil, newError("failed to load geosite: ", country).Base(err)
		}
		return domains, nil
	}
	var isExtDatFile = 0
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
			return nil, newError("invalid external resource: ", domain)
		}
		filename := kv[0]
		country := kv[1]
		domains, err := geosite.LoadGeositeWithAttr(filename, country)
		if err != nil {
			return nil, newError("failed to load external sites: ", country, " from ", filename).Base(err)
		}
		return domains, nil
	}

	domainRule := new(dm.Domain)
	switch {
	case strings.HasPrefix(domain, "regexp:"):
		domainRule.Type = dm.MatchingType_Regex
		domainRule.Value = domain[7:]

	case strings.HasPrefix(domain, "domain:"):
		domainRule.Type = dm.MatchingType_Subdomain
		domainRule.Value = domain[7:]

	case strings.HasPrefix(domain, "full:"):
		domainRule.Type = dm.MatchingType_Full
		domainRule.Value = domain[5:]

	case strings.HasPrefix(domain, "keyword:"):
		domainRule.Type = dm.MatchingType_Keyword
		domainRule.Value = domain[8:]

	case strings.HasPrefix(domain, "dotless:"):
		domainRule.Type = dm.MatchingType_Regex
		switch substr := domain[8:]; {
		case substr == "":
			domainRule.Value = "^[^.]*$"
		case !strings.Contains(substr, "."):
			domainRule.Value = "^[^.]*" + substr + "[^.]*$"
		default:
			return nil, newError("substr in dotless rule should not contain a dot: ", substr)
		}

	default:
		domainRule.Type = dm.MatchingType_Keyword
		domainRule.Value = domain
	}
	return []*dm.Domain{domainRule}, nil
}
