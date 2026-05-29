package strmatcher

// LinearValueMatcher is an implementation of ValueMatcher.
type LinearValueMatcher struct {
	full   *FullMatcherGroup
	domain *DomainMatcherGroup
	substr *SubstrMatcherGroup
	regex  *SimpleMatcherGroup
}

func NewLinearValueMatcher() *LinearValueMatcher {
	return new(LinearValueMatcher)
}

// Add implements ValueMatcher.Add.
func (g *LinearValueMatcher) Add(matcher Matcher, value uint32) {
	switch matcher := matcher.(type) {
	case FullMatcher:
		if g.full == nil {
			g.full = NewFullMatcherGroup()
		}
		g.full.AddFullMatcher(matcher, value)
	case DomainMatcher:
		if g.domain == nil {
			g.domain = NewDomainMatcherGroup()
		}
		g.domain.AddDomainMatcher(matcher, value)
	case SubstrMatcher:
		if g.substr == nil {
			g.substr = new(SubstrMatcherGroup)
		}
		g.substr.AddSubstrMatcher(matcher, value)
	default:
		if g.regex == nil {
			g.regex = new(SimpleMatcherGroup)
		}
		g.regex.AddMatcher(matcher, value)
	}
}

// Build implements ValueMatcher.Build.
func (*LinearValueMatcher) Build() error {
	return nil
}

// Match implements ValueMatcher.Match.
func (g *LinearValueMatcher) Match(input string) []uint32 {
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

// MatchAny implements ValueMatcher.MatchAny.
func (g *LinearValueMatcher) MatchAny(input string) bool {
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
