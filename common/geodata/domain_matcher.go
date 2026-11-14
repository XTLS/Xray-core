package geodata

import (
	"context"
	"runtime"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/geodata/strmatcher"
	"github.com/xtls/xray-core/common/utils"
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
	shared *utils.WeakCacheMap[string, strmatcher.MphValueMatcher]
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
		if g, ok := f.shared.Load(key); ok {
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
			err := loadSiteMatchers(v.Geosite, func(m strmatcher.Matcher) { g.Add(m, uint32(i)) })
			if err != nil {
				return nil, err
			}
		default:
			panic("unknown domain rule type")
		}
	}
	if err := g.Build(); err != nil {
		return nil, err
	}
	if key != "" {
		f.shared.Store(key, g)
	}
	return g, nil
}

type CompactMphDomainMatcherFactory struct {
	sync.Mutex
	shared *utils.WeakCacheMap[string, strmatcher.MphValueMatcher]
}

func (f *CompactMphDomainMatcherFactory) getOrCreateFrom(rule *GeoSiteRule) (*strmatcher.MphValueMatcher, error) {
	key := rule.File + ":" + rule.Code + "@" + rule.Attrs

	f.Lock()
	defer f.Unlock()

	if s, ok := f.shared.Load(key); ok {
		errors.LogDebug(context.Background(), "geodata geosite matcher cache HIT ", key)
		return s, nil
	}
	errors.LogDebug(context.Background(), "geodata geosite matcher cache MISS ", key)

	s := strmatcher.NewMphValueMatcher()
	if err := loadSiteMatchers(rule, func(m strmatcher.Matcher) { s.Add(m, 0) }); err != nil {
		return nil, err
	}
	if err := s.Build(); err != nil {
		return nil, err
	}
	f.shared.Store(key, s)
	return s, nil
}

// BuildMatcher implements DomainMatcherFactory.
func (f *CompactMphDomainMatcherFactory) BuildMatcher(rules []*DomainRule) (DomainMatcher, error) {
	if len(rules) == 0 {
		return nil, errors.New("empty domain rule list")
	}
	compact := new(CompactMphDomainMatcher)
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
			compact.combiner.Add(m, uint32(i))
		default:
			panic("unknown domain rule type")
		}
	}
	return compact, nil
}

type CompactMphDomainMatcher struct {
	custom   strmatcher.ValueMatcher
	combiner strmatcher.MphValueMatcherCombiner
}

// Match implements DomainMatcher.
func (c *CompactMphDomainMatcher) Match(input string) []uint32 {
	result := c.combiner.Match(input)
	if c.custom != nil {
		result = append(c.custom.Match(input), result...)
	}
	return result
}

// MatchAny implements DomainMatcher.
func (c *CompactMphDomainMatcher) MatchAny(input string) bool {
	if c.custom != nil && c.custom.MatchAny(input) {
		return true
	}
	return c.combiner.MatchAny(input)
}

// loadSiteMatchers calls add with a matcher for every domain of the geosite rule and logs the invalid ones.
func loadSiteMatchers(rule *GeoSiteRule, add func(strmatcher.Matcher)) error {
	i := 0
	return loadSite(rule.File, rule.Code, rule.Attrs, func(t Domain_Type, value []byte) {
		m, err := parseDomain(&Domain{Type: t, Value: string(value)})
		if err != nil {
			errors.LogError(context.Background(), "ignore invalid geosite entry in ", rule.File, ":", rule.Code, " at index ", i, ", ", err)
		} else {
			add(m)
		}
		i++
	})
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
		return strmatcher.Domain.New(strings.ToLower(d.Value))
	case Domain_Full:
		return strmatcher.Full.New(strings.ToLower(d.Value))
	default:
		return nil, errors.New("unknown domain type: ", d.Type)
	}
}

func newDomainMatcherFactory() DomainMatcherFactory {
	switch runtime.GOOS {
	case "ios", "android":
		return &CompactMphDomainMatcherFactory{shared: utils.NewWeakCacheMap[string, strmatcher.MphValueMatcher]()}
	default:
		return &MphDomainMatcherFactory{shared: utils.NewWeakCacheMap[string, strmatcher.MphValueMatcher]()}
	}
}
