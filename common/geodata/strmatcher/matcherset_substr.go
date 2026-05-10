package strmatcher

import "strings"

// SubstrMatcherSet is implementation of MatcherSet,
// It is simply implmeneted to comply with the priority specification of Substr matchers.
type SubstrMatcherSet struct {
	patterns []string
}

// AddSubstrMatcher implements MatcherSetForSubstr.AddSubstrMatcher.
func (s *SubstrMatcherSet) AddSubstrMatcher(matcher SubstrMatcher) {
	s.patterns = append(s.patterns, matcher.Pattern())
}

// MatchAny implements MatcherSet.MatchAny.
func (s *SubstrMatcherSet) MatchAny(input string) bool {
	for _, pattern := range s.patterns {
		if strings.Contains(input, pattern) {
			return true
		}
	}
	return false
}
