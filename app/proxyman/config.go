package proxyman

import (
	"github.com/xtls/xray-core/common/matcher/domain"
	"github.com/xtls/xray-core/common/matcher/geoip"
)

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

func (s *AllocationStrategy) GetConcurrencyValue() uint32 {
	if s == nil || s.Concurrency == nil {
		return 3
	}
	return s.Concurrency.Value
}

func (s *AllocationStrategy) GetRefreshValue() uint32 {
	if s == nil || s.Refresh == nil {
		return 5
	}
	return s.Refresh.Value
}

func (c *ReceiverConfig) GetEffectiveSniffingSettings() *SniffingConfig {
	if c.SniffingSettings != nil {
		return c.SniffingSettings
	}

	if len(c.DomainOverride) > 0 {
		var p []string
		for _, kd := range c.DomainOverride {
			switch kd {
			case KnownProtocols_HTTP:
				p = append(p, "http")
			case KnownProtocols_TLS:
				p = append(p, "tls")
			}
		}
		return &SniffingConfig{
			Enabled:             true,
			DestinationOverride: p,
		}
	}

	return nil
}

type SniffingMatcher struct {
	ExDomain *domain.DomainMatcher
	ExIP     *geoip.MultiGeoIPMatcher
}

func NewSniffingMatcher(sc *SniffingConfig) (*SniffingMatcher, error) {
	m := new(SniffingMatcher)

	if sc.DomainsExcluded != nil {
		exDomain, err := domain.NewDomainMatcher(sc.DomainsExcluded)
		if err != nil {
			return nil, newError("failed to parse domain").Base(err)
		}
		m.ExDomain = exDomain
	}
	if sc.IpsExcluded != nil {
		exIP, err := geoip.NewMultiGeoIPMatcher(sc.IpsExcluded, true)
		if err != nil {
			return nil, newError("failed to parse ip").Base(err)
		}
		m.ExIP = exIP
	}
	return m, nil
}
