package strmatcher

import (
	"sort"
	"strings"
)

// SubstrMatcherGroup is implementation of MatcherGroup,
// It is simply implmeneted to comply with the priority specification of Substr matchers.
type SubstrMatcherGroup struct {
	patterns []string
	values   []uint32
}

// AddSubstrMatcher implements MatcherGroupForSubstr.AddSubstrMatcher.
func (g *SubstrMatcherGroup) AddSubstrMatcher(matcher SubstrMatcher, value uint32) {
	g.patterns = append(g.patterns, matcher.Pattern())
	g.values = append(g.values, value)
}

// Match implements MatcherGroup.Match.
func (g *SubstrMatcherGroup) Match(input string) []uint32 {
	var result []uint32
	for i, pattern := range g.patterns {
		for j := strings.LastIndex(input, pattern); j != -1; j = strings.LastIndex(input[:j], pattern) {
			result = append(result, uint32(j)<<16|uint32(i)&0xffff) // uint32: position (higher 16 bit) | patternIdx (lower 16 bit)
		}
	}
	// sort.Slice will trigger allocation no matter what input is. See https://github.com/golang/go/issues/17332
	// We optimize the sorting by length to prevent memory allocation as possible.
	switch len(result) {
	case 0:
		return nil
	case 1:
		// No need to sort
	case 2:
		// Do a simple swap if unsorted
		if result[0] > result[1] {
			result[0], result[1] = result[1], result[0]
		}
	default:
		// Sort the match results in dictionary order, so that:
		//   1. Pattern matched at smaller position (meaning matched further) takes precedence.
		//   2. When patterns matched at same position, pattern with smaller index (meaning inserted early) takes precedence.
		sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	}
	for i, entry := range result {
		result[i] = g.values[entry&0xffff] // Get pattern value from its index (the lower 16 bit)
	}
	return result
}

// MatchAny implements MatcherGroup.MatchAny.
func (g *SubstrMatcherGroup) MatchAny(input string) bool {
	for _, pattern := range g.patterns {
		if strings.Contains(input, pattern) {
			return true
		}
	}
	return false
}
