package geodata

import (
	"context"
	"runtime"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/geodata/strmatcher"
)

type DomainMatcher interface {
	Match(input string) []uint32
	MatchAny(input string) bool
}

type DomainMatcherFactory interface {
	BuildMatcher(rules []*DomainRule) (DomainMatcher, error)
}

type MphDomainMatcherFactory struct{}

// BuildMatcher implements DomainMatcherFactory.
func (f *MphDomainMatcherFactory) BuildMatcher(rules []*DomainRule) (DomainMatcher, error) {
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

type CompactDomainMatcherFactory struct {
	sync.Mutex
	shared map[string]strmatcher.MatcherGroup // TODO: cleanup
}

func (f *CompactDomainMatcherFactory) getOrCreateFrom(rule *GeoSiteRule) (strmatcher.MatcherGroup, error) {
	key := rule.File + ":" + rule.Code + "@" + rule.Attrs

	f.Lock()
	defer f.Unlock()

	if m := f.shared[key]; m != nil {
		return m, nil
	}

	g := strmatcher.NewLinearValueMatcher()
	domains, err := loadSiteWithAttrs(rule.File, rule.Code, rule.Attrs)
	if err != nil {
		return nil, err
	}
	for i, d := range domains {
		domains[i] = nil // peak mem
		m, err := parseDomain(d)
		if err != nil {
			errors.LogError(context.Background(), "ignore invalid geosite entry in ", rule.File, ":", rule.Code, " at index ", i, ", ", err)
			continue
		}
		g.Add(m, 0)
	}
	f.shared[key] = g
	return g, err
}

// BuildMatcher implements DomainMatcherFactory.
func (f *CompactDomainMatcherFactory) BuildMatcher(rules []*DomainRule) (DomainMatcher, error) {
	compact := &CompactDomainMatcher{
		matchers: make([]strmatcher.MatcherGroup, 0, len(rules)),
		values:   make([]uint32, 0, len(rules)),
	}
	custom := strmatcher.NewLinearValueMatcher()
	var idx uint32
	for _, r := range rules {
		switch v := r.Value.(type) {
		case *DomainRule_Custom:
			m, err := parseDomain(v.Custom)
			if err != nil {
				return nil, err
			}
			custom.Add(m, 0)
		case *DomainRule_Geosite:
			m, err := f.getOrCreateFrom(v.Geosite)
			if err != nil {
				return nil, err
			}
			compact.matchers = append(compact.matchers, m)
			compact.values = append(compact.values, idx)
			idx++
		default:
			panic("unknown domain rule type")
		}
	}
	if len(compact.matchers) != len(rules) {
		compact.matchers = append(compact.matchers, custom)
		compact.values = append(compact.values, idx+1)
	}
	return compact, nil
}

type CompactDomainMatcher struct {
	matchers []strmatcher.MatcherGroup
	values   []uint32
}

func (c *CompactDomainMatcher) Add(matcher strmatcher.MatcherGroup, value uint32) {
	c.matchers = append(c.matchers, matcher)
	c.values = append(c.values, value)
}

// Match implements DomainMatcher.
func (c *CompactDomainMatcher) Match(input string) []uint32 {
	result := make([]uint32, 0)
	for i, m := range c.matchers {
		if m.MatchAny(input) {
			result = append(result, c.values[i])
		}
	}
	return result
}

// MatchAny implements DomainMatcher.
func (c *CompactDomainMatcher) MatchAny(input string) bool {
	for _, m := range c.matchers {
		if m.MatchAny(input) {
			return true
		}
	}
	return false
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

func newDomainMatcherFactory() DomainMatcherFactory {
	switch runtime.GOOS {
	case "ios":
		return &CompactDomainMatcherFactory{shared: make(map[string]strmatcher.MatcherGroup)}
	default:
		return &MphDomainMatcherFactory{}
	}
}
