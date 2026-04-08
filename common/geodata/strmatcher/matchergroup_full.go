package strmatcher

// FullMatcherGroup is an implementation of MatcherGroup.
// It uses a hash table to facilitate exact match lookup.
type FullMatcherGroup struct {
	matchers map[string][]uint32
}

func NewFullMatcherGroup() *FullMatcherGroup {
	return &FullMatcherGroup{
		matchers: make(map[string][]uint32),
	}
}

// AddFullMatcher implements MatcherGroupForFull.AddFullMatcher.
func (g *FullMatcherGroup) AddFullMatcher(matcher FullMatcher, value uint32) {
	domain := matcher.Pattern()
	g.matchers[domain] = append(g.matchers[domain], value)
}

// Match implements MatcherGroup.Match.
func (g *FullMatcherGroup) Match(input string) []uint32 {
	return g.matchers[input]
}

// MatchAny implements MatcherGroup.Any.
func (g *FullMatcherGroup) MatchAny(input string) bool {
	_, found := g.matchers[input]
	return found
}
