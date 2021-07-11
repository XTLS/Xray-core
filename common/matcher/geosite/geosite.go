package geosite

import "github.com/xtls/xray-core/common/matcher/domain"

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

func ToDomains(dms []*Domain) []*domain.Domain {
	dm := make([]*domain.Domain, len(dms))

	for idx, entry := range dms {
		dm[idx] = entry.ToDomain()
	}

	return dm
}

func (d *Domain) ToDomain() *domain.Domain {
	return &domain.Domain{Type: d.Type.ToMatchingType(), Value: d.Value}
}

func (t Domain_Type) ToMatchingType() domain.MatchingType {
	switch t {
	case Domain_Plain:
		return domain.MatchingType_Keyword
	case Domain_Regex:
		return domain.MatchingType_Regex
	case Domain_Domain:
		return domain.MatchingType_Subdomain
	case Domain_Full:
		return domain.MatchingType_Full
	}
	panic("impossible")
}
