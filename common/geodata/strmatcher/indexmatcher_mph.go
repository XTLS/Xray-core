package strmatcher

import "runtime"

// A MphIndexMatcher is divided into three parts:
// 1. `full` and `domain` patterns are matched by Rabin-Karp algorithm and minimal perfect hash table;
// 2. `substr` patterns are matched by ac automaton;
// 3. `regex` patterns are matched with the regex library.
type MphIndexMatcher struct {
	count uint32
	mph   *MphMatcherGroup
	ac    *ACAutomatonMatcherGroup
	regex *SimpleMatcherGroup
}

func NewMphIndexMatcher() *MphIndexMatcher {
	return new(MphIndexMatcher)
}

// Add implements IndexMatcher.Add.
func (g *MphIndexMatcher) Add(matcher Matcher) uint32 {
	g.count++
	index := g.count

	switch matcher := matcher.(type) {
	case FullMatcher:
		if g.mph == nil {
			g.mph = NewMphMatcherGroup()
		}
		g.mph.AddFullMatcher(matcher, index)
	case DomainMatcher:
		if g.mph == nil {
			g.mph = NewMphMatcherGroup()
		}
		g.mph.AddDomainMatcher(matcher, index)
	case SubstrMatcher:
		if g.ac == nil {
			g.ac = NewACAutomatonMatcherGroup()
		}
		g.ac.AddSubstrMatcher(matcher, index)
	case *RegexMatcher:
		if g.regex == nil {
			g.regex = &SimpleMatcherGroup{}
		}
		g.regex.AddMatcher(matcher, index)
	}

	return index
}

// Build implements IndexMatcher.Build.
func (g *MphIndexMatcher) Build() error {
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

// Match implements IndexMatcher.Match.
func (g *MphIndexMatcher) Match(input string) []uint32 {
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

// MatchAny implements IndexMatcher.MatchAny.
func (g *MphIndexMatcher) MatchAny(input string) bool {
	if g.mph != nil && g.mph.MatchAny(input) {
		return true
	}
	if g.ac != nil && g.ac.MatchAny(input) {
		return true
	}
	return g.regex != nil && g.regex.MatchAny(input)
}

// Size implements IndexMatcher.Size.
func (g *MphIndexMatcher) Size() uint32 {
	return g.count
}
