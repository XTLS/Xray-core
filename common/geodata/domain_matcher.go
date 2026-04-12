package geodata

import (
	"context"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/geodata/strmatcher"
)

type DomainMatcher interface {
	Match(input string) []uint32
	MatchAny(input string) bool
}

func buildDomainMatcher(rules []*DomainRule) (DomainMatcher, error) {
	g := strmatcher.NewMphValueMatcher()
	for i, r := range rules {
		switch v := r.Value.(type) {
		case *DomainRule_Custom:
			m, err := parseDomain(v.Custom)
			if err != nil {
				return nil, err
			}
			g.Add(m, uint32(i))
		case *DomainRule_Geosite:
			domains, err := loadSiteWithAttrs(v.Geosite.File, v.Geosite.Code, v.Geosite.Attrs)
			if err != nil {
				return nil, err
			}
			for j, d := range domains {
				domains[j] = nil // peak mem
				m, err := parseDomain(d)
				if err != nil {
					errors.LogError(context.Background(), "ignore invalid geosite entry in ", v.Geosite.File, ":", v.Geosite.Code, " at index ", j, ", ", err)
					continue
				}
				g.Add(m, uint32(i))
			}
		default:
			panic("unknown domain rule type")
		}
	}
	if err := g.Build(); err != nil {
		return nil, err
	}
	return g, nil
}

func parseDomain(d *Domain) (strmatcher.Matcher, error) {
	if d == nil {
		return nil, errors.New("domain must not be nil")
	}
	switch d.Type {
	case Domain_Substr:
		return strmatcher.Substr.New(strings.ToLower(d.Value))
	case Domain_Regex:
		return strmatcher.Regex.New(d.Value)
	case Domain_Domain:
		return strmatcher.Domain.New(d.Value)
	case Domain_Full:
		return strmatcher.Full.New(strings.ToLower(d.Value))
	default:
		return nil, errors.New("unknown domain type: ", d.Type)
	}
}
