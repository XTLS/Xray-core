package strmatcher

// SimpleMatcherSet is an implementation of MatcherSet.
// It simply stores all matchers in an array and sequentially matches them.
type SimpleMatcherSet struct {
	matchers []Matcher
}

// AddMatcher implements MatcherSetForAll.AddMatcher.
func (s *SimpleMatcherSet) AddMatcher(matcher Matcher) {
	s.matchers = append(s.matchers, matcher)
}

// MatchAny implements MatcherSet.MatchAny.
func (s *SimpleMatcherSet) MatchAny(input string) bool {
	for _, m := range s.matchers {
		if m.Match(input) {
			return true
		}
	}
	return false
}
