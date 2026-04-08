package strmatcher

type matcherEntry struct {
	matcher Matcher
	value   uint32
}

// SimpleMatcherGroup is an implementation of MatcherGroup.
// It simply stores all matchers in an array and sequentially matches them.
type SimpleMatcherGroup struct {
	matchers []matcherEntry
}

// AddMatcher implements MatcherGroupForAll.AddMatcher.
func (g *SimpleMatcherGroup) AddMatcher(matcher Matcher, value uint32) {
	g.matchers = append(g.matchers, matcherEntry{
		matcher: matcher,
		value:   value,
	})
}

// Match implements MatcherGroup.Match.
func (g *SimpleMatcherGroup) Match(input string) []uint32 {
	result := []uint32{}
	for _, e := range g.matchers {
		if e.matcher.Match(input) {
			result = append(result, e.value)
		}
	}
	return result
}

// MatchAny implements MatcherGroup.MatchAny.
func (g *SimpleMatcherGroup) MatchAny(input string) bool {
	for _, e := range g.matchers {
		if e.matcher.Match(input) {
			return true
		}
	}
	return false
}
