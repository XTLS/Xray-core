package strmatcher

// LinearIndexMatcher is an implementation of IndexMatcher.
type LinearIndexMatcher struct {
	count  uint32
	full   *FullMatcherGroup
	domain *DomainMatcherGroup
	substr *SubstrMatcherGroup
	regex  *SimpleMatcherGroup
}

func NewLinearIndexMatcher() *LinearIndexMatcher {
	return new(LinearIndexMatcher)
}

// Add implements IndexMatcher.Add.
func (g *LinearIndexMatcher) Add(matcher Matcher) uint32 {
	g.count++
	index := g.count

	switch matcher := matcher.(type) {
	case FullMatcher:
		if g.full == nil {
			g.full = NewFullMatcherGroup()
		}
		g.full.AddFullMatcher(matcher, index)
	case DomainMatcher:
		if g.domain == nil {
			g.domain = NewDomainMatcherGroup()
		}
		g.domain.AddDomainMatcher(matcher, index)
	case SubstrMatcher:
		if g.substr == nil {
			g.substr = new(SubstrMatcherGroup)
		}
		g.substr.AddSubstrMatcher(matcher, index)
	default:
		if g.regex == nil {
			g.regex = new(SimpleMatcherGroup)
		}
		g.regex.AddMatcher(matcher, index)
	}

	return index
}

// Build implements IndexMatcher.Build.
func (*LinearIndexMatcher) Build() error {
	return nil
}

// Match implements IndexMatcher.Match.
func (g *LinearIndexMatcher) Match(input string) []uint32 {
	// Allocate capacity to prevent matches escaping to heap
	result := make([][]uint32, 0, 5)
	if g.full != nil {
		if matches := g.full.Match(input); len(matches) > 0 {
			result = append(result, matches)
		}
	}
	if g.domain != nil {
		if matches := g.domain.Match(input); len(matches) > 0 {
			result = append(result, matches)
		}
	}
	if g.substr != nil {
		if matches := g.substr.Match(input); len(matches) > 0 {
			result = append(result, matches)
		}
	}
	if g.regex != nil {
		if matches := g.regex.Match(input); len(matches) > 0 {
			result = append(result, matches)
		}
	}
	return CompositeMatches(result)
}

// MatchAny implements IndexMatcher.MatchAny.
func (g *LinearIndexMatcher) MatchAny(input string) bool {
	if g.full != nil && g.full.MatchAny(input) {
		return true
	}
	if g.domain != nil && g.domain.MatchAny(input) {
		return true
	}
	if g.substr != nil && g.substr.MatchAny(input) {
		return true
	}
	return g.regex != nil && g.regex.MatchAny(input)
}

// Size implements IndexMatcher.Size.
func (g *LinearIndexMatcher) Size() uint32 {
	return g.count
}
