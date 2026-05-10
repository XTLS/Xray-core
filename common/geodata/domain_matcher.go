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
	// Match returns the indices of all rules that match the input domain.
	// The returned slice is owned by the caller and may be safely modified.
	// Note: the slice may contain duplicates and the order is unspecified.
	Match(input string) []uint32

	MatchAny(input string) bool
}

type DomainMatcherFactory interface {
	BuildMatcher(rules []*DomainRule) (DomainMatcher, error)
}

type MphDomainMatcherFactory struct {
	sync.Mutex
	shared map[string]strmatcher.MatcherGroup // TODO: cleanup
}

func buildDomainRulesKey(rules []*DomainRule) string {
	var sb strings.Builder
	cache := false
	for _, r := range rules {
		switch v := r.Value.(type) {
		case *DomainRule_Custom:
			sb.WriteString(v.Custom.Type.String())
			sb.WriteString(":")
			sb.WriteString(v.Custom.Value)
			sb.WriteString(",")
		case *DomainRule_Geosite:
			cache = true
			sb.WriteString(v.Geosite.File)
			sb.WriteString(":")
			sb.WriteString(v.Geosite.Code)
			sb.WriteString("@")
			sb.WriteString(v.Geosite.Attrs)
			sb.WriteString(",")
		default:
			panic("unknown domain rule type")
		}
	}
	if !cache {
		return ""
	}
	return sb.String()
}

// BuildMatcher implements DomainMatcherFactory.
func (f *MphDomainMatcherFactory) BuildMatcher(rules []*DomainRule) (DomainMatcher, error) {
	if len(rules) == 0 {
		return nil, errors.New("empty domain rule list")
	}
	key := buildDomainRulesKey(rules)
	if key != "" {
		f.Lock()
		defer f.Unlock()
		if g := f.shared[key]; g != nil {
			errors.LogDebug(context.Background(), "geodata mph domain matcher cache HIT for ", len(rules), " rules")
			return g, nil
		}
		errors.LogDebug(context.Background(), "geodata mph domain matcher cache MISS for ", len(rules), " rules")
	}
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
	if key != "" {
		f.shared[key] = g
	}
	return g, nil
}

type CompactDomainMatcherFactory struct {
	sync.Mutex
	shared map[string]strmatcher.MatcherSet // TODO: cleanup
}

func (f *CompactDomainMatcherFactory) getOrCreateFrom(rule *GeoSiteRule) (strmatcher.MatcherSet, error) {
	key := rule.File + ":" + rule.Code + "@" + rule.Attrs

	f.Lock()
	defer f.Unlock()

	if s := f.shared[key]; s != nil {
		errors.LogDebug(context.Background(), "geodata geosite matcher cache HIT ", key)
		return s, nil
	}
	errors.LogDebug(context.Background(), "geodata geosite matcher cache MISS ", key)

	s := strmatcher.NewLinearAnyMatcher()
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
		s.Add(m)
	}
	f.shared[key] = s
	return s, err
}

// BuildMatcher implements DomainMatcherFactory.
func (f *CompactDomainMatcherFactory) BuildMatcher(rules []*DomainRule) (DomainMatcher, error) {
	if len(rules) == 0 {
		return nil, errors.New("empty domain rule list")
	}
	compact := &CompactDomainMatcher{
		matchers: make([]strmatcher.MatcherSet, 0, len(rules)),
		values:   make([]uint32, 0, len(rules)),
	}
	for i, r := range rules {
		switch v := r.Value.(type) {
		case *DomainRule_Custom:
			m, err := parseDomain(v.Custom)
			if err != nil {
				return nil, err
			}
			if compact.custom == nil {
				compact.custom = strmatcher.NewLinearValueMatcher()
			}
			compact.custom.Add(m, uint32(i))
		case *DomainRule_Geosite:
			m, err := f.getOrCreateFrom(v.Geosite)
			if err != nil {
				return nil, err
			}
			compact.matchers = append(compact.matchers, m)
			compact.values = append(compact.values, uint32(i))
		default:
			panic("unknown domain rule type")
		}
	}
	return compact, nil
}

type CompactDomainMatcher struct {
	custom   strmatcher.ValueMatcher
	matchers []strmatcher.MatcherSet
	values   []uint32
}

// Match implements DomainMatcher.
func (c *CompactDomainMatcher) Match(input string) []uint32 {
	var result []uint32
	if c.custom != nil {
		result = append(result, c.custom.Match(input)...)
	}
	for i, m := range c.matchers {
		if m.MatchAny(input) {
			result = append(result, c.values[i])
		}
	}
	return result
}

// MatchAny implements DomainMatcher.
func (c *CompactDomainMatcher) MatchAny(input string) bool {
	if c.custom != nil && c.custom.MatchAny(input) {
		return true
	}
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
	case "ios", "android":
		return &CompactDomainMatcherFactory{shared: make(map[string]strmatcher.MatcherSet)}
	default:
		return &MphDomainMatcherFactory{shared: make(map[string]strmatcher.MatcherGroup)}
	}
}
