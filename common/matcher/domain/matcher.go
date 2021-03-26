package domain

import (
	"github.com/xtls/xray-core/common/matcher/str"
	"github.com/xtls/xray-core/features/routing"
	"strings"
)

var matcherTypeMap = map[MatchingType]str.Type{
	MatchingType_Keyword:   str.Substr,
	MatchingType_Regex:     str.Regex,
	MatchingType_Subdomain: str.Domain,
	MatchingType_Full:      str.Full,
}

func domainToMatcher(domain *Domain) (str.Matcher, error) {
	matcherType, f := matcherTypeMap[domain.Type]
	if !f {
		return nil, newError("unsupported domain type", domain.Type)
	}

	matcher, err := matcherType.New(domain.Value)
	if err != nil {
		return nil, newError("failed to create domain matcher").Base(err)
	}

	return matcher, nil
}

type DomainMatcher struct {
	matchers str.IndexMatcher
}

func NewDomainMatcher(domains []*Domain) (*DomainMatcher, error) {
	g := new(str.MatcherGroup)
	for _, d := range domains {
		m, err := domainToMatcher(d)
		if err != nil {
			return nil, err
		}
		g.Add(m)
	}

	return &DomainMatcher{
		matchers: g,
	}, nil
}

func (m *DomainMatcher) ApplyDomain(domain string) bool {
	return len(m.matchers.Match(domain)) > 0
}

// Apply implements Condition.
func (m *DomainMatcher) Apply(ctx routing.Context) bool {
	domain := ctx.GetTargetDomain()
	if len(domain) == 0 {
		return false
	}
	return m.ApplyDomain(strings.ToLower(domain))
}
