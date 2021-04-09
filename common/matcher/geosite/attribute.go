package geosite

import "strings"

type AttributeList struct {
	matcher []AttributeMatcher
}

func (al *AttributeList) Match(domain *Domain) bool {
	for _, matcher := range al.matcher {
		if !matcher.Match(domain) {
			return false
		}
	}
	return true
}

func (al *AttributeList) IsEmpty() bool {
	return len(al.matcher) == 0
}

type AttributeMatcher interface {
	Match(*Domain) bool
}

type BooleanMatcher string

func (m BooleanMatcher) Match(domain *Domain) bool {
	for _, attr := range domain.Attribute {
		if strings.EqualFold(attr.GetKey(), string(m)) {
			return true
		}
	}
	return false
}
