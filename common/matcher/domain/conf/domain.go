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
		regexpVal := domain[7:]
		if len(regexpVal) == 0 {
			return nil, newError("empty regexp type of rule: ", domain)
		}
		domainRule.Type = dm.MatchingType_Regex
		domainRule.Value = regexpVal

	case strings.HasPrefix(domain, "domain:"):
		domainName := domain[7:]
		if len(domainName) == 0 {
			return nil, newError("empty domain type of rule: ", domain)
		}
		domainRule.Type = dm.MatchingType_Subdomain
		domainRule.Value = domainName

	case strings.HasPrefix(domain, "full:"):
		fullVal := domain[5:]
		if len(fullVal) == 0 {
			return nil, newError("empty full domain type of rule: ", domain)
		}
		domainRule.Type = dm.MatchingType_Full
		domainRule.Value = fullVal

	case strings.HasPrefix(domain, "keyword:"):
		keywordVal := domain[8:]
		if len(keywordVal) == 0 {
			return nil, newError("empty keyword type of rule: ", domain)
		}
		domainRule.Type = dm.MatchingType_Keyword
		domainRule.Value = keywordVal

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
