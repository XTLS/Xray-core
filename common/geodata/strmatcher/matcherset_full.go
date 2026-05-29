package strmatcher

// FullMatcherSet is an implementation of MatcherSet.
// It uses a hash table to facilitate exact match lookup.
type FullMatcherSet struct {
	matchers map[string]struct{}
}

func NewFullMatcherSet() *FullMatcherSet {
	return &FullMatcherSet{
		matchers: make(map[string]struct{}),
	}
}

// AddFullMatcher implements MatcherSetForFull.AddFullMatcher.
func (s *FullMatcherSet) AddFullMatcher(matcher FullMatcher) {
	s.matchers[matcher.Pattern()] = struct{}{}
}

// MatchAny implements MatcherSet.Any.
func (s *FullMatcherSet) MatchAny(input string) bool {
	_, found := s.matchers[input]
	return found
}
