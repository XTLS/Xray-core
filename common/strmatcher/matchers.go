package strmatcher

import (
	"regexp"
	"strings"
)

type fullMatcher string

func (m fullMatcher) Match(s string) bool {
	return string(m) == s
}

func (m fullMatcher) String() string {
	return "full:" + string(m)
}

func (m fullMatcher) Restore() *RestoreDomain {
	return &RestoreDomain{
		Value:      string(m),
		DomainType: RestoreDomainTypePlain,
	}
}

type substrMatcher string

func (m substrMatcher) Match(s string) bool {
	return strings.Contains(s, string(m))
}

func (m substrMatcher) String() string {
	return "keyword:" + string(m)
}

func (m substrMatcher) Restore() *RestoreDomain {
	return &RestoreDomain{
		Value:      string(m),
		DomainType: RestoreDomainTypePlain,
	}
}

type domainMatcher string

func (m domainMatcher) Match(s string) bool {
	pattern := string(m)
	if !strings.HasSuffix(s, pattern) {
		return false
	}
	return len(s) == len(pattern) || s[len(s)-len(pattern)-1] == '.'
}

func (m domainMatcher) String() string {
	return "domain:" + string(m)
}

func (m domainMatcher) Restore() *RestoreDomain {
	return &RestoreDomain{
		Value:      string(m),
		DomainType: RestoreDomainTypeDomain,
	}
}

type regexMatcher struct {
	pattern *regexp.Regexp
}

func (m *regexMatcher) Match(s string) bool {
	return m.pattern.MatchString(s)
}

func (m *regexMatcher) String() string {
	return "regexp:" + m.pattern.String()
}

func (m *regexMatcher) Restore() *RestoreDomain {
	return &RestoreDomain{
		Value:      m.pattern.String(),
		DomainType: RestoreDomainTypeRegex,
	}
}
