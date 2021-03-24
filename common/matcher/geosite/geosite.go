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
	return &domain.Domain{Type: d.Type, Value: d.Value}
}
