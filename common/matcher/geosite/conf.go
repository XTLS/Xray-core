package geosite

import (
	"strings"

	dm "github.com/xtls/xray-core/common/matcher/domain"
)

func LoadGeositeWithAttr(file string, siteWithAttr string) ([]*dm.Domain, error) {
	parts := strings.Split(siteWithAttr, "@")
	if len(parts) == 0 {
		return nil, newError("empty site")
	}
	country := strings.ToUpper(parts[0])
	attrs := parseAttrs(parts[1:])
	domains, err := loadSite(file, country)
	if err != nil {
		return nil, err
	}

	if attrs.IsEmpty() {
		return ToDomains(domains), nil
	}

	filteredDomains := make([]*dm.Domain, 0, len(domains))
	for _, domain := range domains {
		if attrs.Match(domain) {
			filteredDomains = append(filteredDomains, domain.ToDomain())
		}
	}

	return filteredDomains, nil
}

func parseAttrs(attrs []string) *AttributeList {
	al := new(AttributeList)
	for _, attr := range attrs {
		lc := strings.ToLower(attr)
		al.matcher = append(al.matcher, BooleanMatcher(lc))
	}
	return al
}
