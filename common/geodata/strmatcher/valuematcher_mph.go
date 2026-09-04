package strmatcher

import "runtime"

// A MphValueMatcher is divided into three parts:
// 1. `full` and `domain` patterns are matched by Rabin-Karp algorithm and minimal perfect hash table;
// 2. `substr` patterns are matched by ac automaton;
// 3. `regex` patterns are matched with the regex library.
type MphValueMatcher struct {
	mph   *MphMatcherGroup
	ac    *ACAutomatonMatcherGroup
	regex *SimpleMatcherGroup
}

func NewMphValueMatcher() *MphValueMatcher {
	return new(MphValueMatcher)
}

// Add implements ValueMatcher.Add.
func (g *MphValueMatcher) Add(matcher Matcher, value uint32) {
	switch matcher := matcher.(type) {
	case FullMatcher:
		if g.mph == nil {
			g.mph = NewMphMatcherGroup()
		}
		g.mph.AddFullMatcher(matcher, value)
	case DomainMatcher:
		if g.mph == nil {
			g.mph = NewMphMatcherGroup()
		}
		g.mph.AddDomainMatcher(matcher, value)
	case SubstrMatcher:
		if g.ac == nil {
			g.ac = NewACAutomatonMatcherGroup()
		}
		g.ac.AddSubstrMatcher(matcher, value)
	case *RegexMatcher:
		if g.regex == nil {
			g.regex = &SimpleMatcherGroup{}
		}
		g.regex.AddMatcher(matcher, value)
	}
}

// Build implements ValueMatcher.Build.
func (g *MphValueMatcher) Build() error {
	if g.mph != nil {
		runtime.GC() // peak mem
		g.mph.Build()
	}
	runtime.GC() // peak mem
	if g.ac != nil {
		g.ac.Build()
		runtime.GC() // peak mem
	}
	return nil
}

// Match implements ValueMatcher.Match.
func (g *MphValueMatcher) Match(input string) []uint32 {
	result := make([][]uint32, 0, 5)
	if g.mph != nil {
		if matches := g.mph.Match(input); len(matches) > 0 {
			result = append(result, matches)
		}
	}
	if g.ac != nil {
		if matches := g.ac.Match(input); len(matches) > 0 {
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
func (g *MphValueMatcher) MatchAny(input string) bool {
	if g.mph != nil && g.mph.MatchAny(input) {
		return true
	}
	if g.ac != nil && g.ac.MatchAny(input) {
		return true
	}
	return g.regex != nil && g.regex.MatchAny(input)
}
