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
		if err := g.mph.Build(); err != nil {
			return err
		}
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
	var result []uint32
	if g.mph != nil {
		result = g.mph.Match(input) // a new slice, returned without another copy
	}
	if g.ac != nil {
		result = append(result, g.ac.Match(input)...)
	}
	if g.regex != nil {
		result = append(result, g.regex.Match(input)...)
	}
	return result
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

func (g *MphValueMatcher) matchAnyHashed(input string, parents []mphSuffix, h, mul uint64) bool {
	if g.mph != nil && g.mph.matchAnyHashed(input, parents, h, mul) {
		return true
	}
	if g.ac != nil && g.ac.MatchAny(input) {
		return true
	}
	return g.regex != nil && g.regex.MatchAny(input)
}

// MphValueMatcherCombiner combines several built MphValueMatchers, each bound to one value, and matches an input
// against them as their MatchAny would, hashing the input once for all of them.
type MphValueMatcherCombiner struct {
	matchers []*MphValueMatcher
	values   []uint32
}

// Add adds a built matcher that stands for value.
func (s *MphValueMatcherCombiner) Add(m *MphValueMatcher, value uint32) {
	s.matchers = append(s.matchers, m)
	s.values = append(s.values, value)
}

// Match returns the values of the matchers that match input, in Add order.
func (s *MphValueMatcherCombiner) Match(input string) []uint32 {
	if len(s.matchers) == 0 {
		return nil
	}
	var stack [16]mphSuffix
	mul := mphMultipliers[0]
	parents, h := mphSuffixes(stack[:0], mul, input)
	var result []uint32
	for i, m := range s.matchers {
		if m.matchAnyHashed(input, parents, h, mul) {
			result = append(result, s.values[i])
		}
	}
	return result
}

// MatchAny returns true as soon as one matcher matches input.
func (s *MphValueMatcherCombiner) MatchAny(input string) bool {
	switch len(s.matchers) {
	case 0:
		return false
	case 1:
		return s.matchers[0].MatchAny(input) // nothing to share, and it stops at the first matching suffix
	}
	var stack [16]mphSuffix
	mul := mphMultipliers[0]
	parents, h := mphSuffixes(stack[:0], mul, input)
	for _, m := range s.matchers {
		if m.matchAnyHashed(input, parents, h, mul) {
			return true
		}
	}
	return false
}
