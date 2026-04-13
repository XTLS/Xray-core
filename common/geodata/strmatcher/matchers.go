package strmatcher

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// FullMatcher is an implementation of Matcher.
type FullMatcher string

func (FullMatcher) Type() Type {
	return Full
}

func (m FullMatcher) Pattern() string {
	return string(m)
}

func (m FullMatcher) String() string {
	return "full:" + m.Pattern()
}

func (m FullMatcher) Match(s string) bool {
	return string(m) == s
}

// DomainMatcher is an implementation of Matcher.
type DomainMatcher string

func (DomainMatcher) Type() Type {
	return Domain
}

func (m DomainMatcher) Pattern() string {
	return string(m)
}

func (m DomainMatcher) String() string {
	return "domain:" + m.Pattern()
}

func (m DomainMatcher) Match(s string) bool {
	pattern := m.Pattern()
	if !strings.HasSuffix(s, pattern) {
		return false
	}
	return len(s) == len(pattern) || s[len(s)-len(pattern)-1] == '.'
}

// SubstrMatcher is an implementation of Matcher.
type SubstrMatcher string

func (SubstrMatcher) Type() Type {
	return Substr
}

func (m SubstrMatcher) Pattern() string {
	return string(m)
}

func (m SubstrMatcher) String() string {
	return "keyword:" + m.Pattern()
}

func (m SubstrMatcher) Match(s string) bool {
	return strings.Contains(s, m.Pattern())
}

// RegexMatcher is an implementation of Matcher.
type RegexMatcher struct {
	pattern *regexp.Regexp
}

func (*RegexMatcher) Type() Type {
	return Regex
}

func (m *RegexMatcher) Pattern() string {
	return m.pattern.String()
}

func (m *RegexMatcher) String() string {
	return "regexp:" + m.Pattern()
}

func (m *RegexMatcher) Match(s string) bool {
	return m.pattern.MatchString(s)
}

// New creates a new Matcher based on the given pattern.
func (t Type) New(pattern string) (Matcher, error) {
	switch t {
	case Full:
		return FullMatcher(pattern), nil
	case Substr:
		return SubstrMatcher(pattern), nil
	case Domain:
		pattern, err := ToDomain(pattern)
		if err != nil {
			return nil, err
		}
		return DomainMatcher(pattern), nil
	case Regex: // 1. regex matching is case-sensitive
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		return &RegexMatcher{pattern: regex}, nil
	default:
		return nil, errors.New("unknown matcher type")
	}
}

// NewDomainPattern creates a new Matcher based on the given domain pattern.
// It works like `Type.New`, but will do validation and conversion to ensure it's a valid domain pattern.
func (t Type) NewDomainPattern(pattern string) (Matcher, error) {
	switch t {
	case Full:
		pattern, err := ToDomain(pattern)
		if err != nil {
			return nil, err
		}
		return FullMatcher(pattern), nil
	case Substr:
		pattern, err := ToDomain(pattern)
		if err != nil {
			return nil, err
		}
		return SubstrMatcher(pattern), nil
	case Domain:
		pattern, err := ToDomain(pattern)
		if err != nil {
			return nil, err
		}
		return DomainMatcher(pattern), nil
	case Regex: // Regex's charset not in LDH subset
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		return &RegexMatcher{pattern: regex}, nil
	default:
		return nil, errors.New("unknown matcher type")
	}
}

// ToDomain converts input pattern to a domain string, and return error if such a conversion cannot be made.
//  1. Conforms to Letter-Digit-Hyphen (LDH) subset (https://tools.ietf.org/html/rfc952):
//     * Letters A to Z (no distinction between uppercase and lowercase, we convert to lowers)
//     * Digits 0 to 9
//     * Hyphens(-) and Periods(.)
//  2. If any non-ASCII characters, domain are converted from Internationalized domain name to Punycode.
func ToDomain(pattern string) (string, error) {
	for {
		isASCII, hasUpper := true, false
		for i := 0; i < len(pattern); i++ {
			c := pattern[i]
			if c >= utf8.RuneSelf {
				isASCII = false
				break
			}
			switch {
			case 'A' <= c && c <= 'Z':
				hasUpper = true
			case 'a' <= c && c <= 'z':
			case '0' <= c && c <= '9':
			case c == '-':
			case c == '.':
			default:
				return "", errors.New("pattern string does not conform to Letter-Digit-Hyphen (LDH) subset")
			}
		}
		if !isASCII {
			var err error
			pattern, err = idna.Punycode.ToASCII(pattern)
			if err != nil {
				return "", err
			}
			continue
		}
		if hasUpper {
			pattern = strings.ToLower(pattern)
		}
		break
	}
	return pattern, nil
}

// MatcherGroupForAll is an interface indicating a MatcherGroup could accept all types of matchers.
type MatcherGroupForAll interface {
	AddMatcher(matcher Matcher, value uint32)
}

// MatcherGroupForFull is an interface indicating a MatcherGroup could accept FullMatchers.
type MatcherGroupForFull interface {
	AddFullMatcher(matcher FullMatcher, value uint32)
}

// MatcherGroupForDomain is an interface indicating a MatcherGroup could accept DomainMatchers.
type MatcherGroupForDomain interface {
	AddDomainMatcher(matcher DomainMatcher, value uint32)
}

// MatcherGroupForSubstr is an interface indicating a MatcherGroup could accept SubstrMatchers.
type MatcherGroupForSubstr interface {
	AddSubstrMatcher(matcher SubstrMatcher, value uint32)
}

// MatcherGroupForRegex is an interface indicating a MatcherGroup could accept RegexMatchers.
type MatcherGroupForRegex interface {
	AddRegexMatcher(matcher *RegexMatcher, value uint32)
}

// AddMatcherToGroup is a helper function to try to add a Matcher to any kind of MatcherGroup.
// It returns error if the MatcherGroup does not accept the provided Matcher's type.
// This function is provided to help writing code to test a MatcherGroup.
func AddMatcherToGroup(g MatcherGroup, matcher Matcher, value uint32) error {
	if g, ok := g.(IndexMatcher); ok {
		g.Add(matcher)
		return nil
	}
	if g, ok := g.(MatcherGroupForAll); ok {
		g.AddMatcher(matcher, value)
		return nil
	}
	switch matcher := matcher.(type) {
	case FullMatcher:
		if g, ok := g.(MatcherGroupForFull); ok {
			g.AddFullMatcher(matcher, value)
			return nil
		}
	case DomainMatcher:
		if g, ok := g.(MatcherGroupForDomain); ok {
			g.AddDomainMatcher(matcher, value)
			return nil
		}
	case SubstrMatcher:
		if g, ok := g.(MatcherGroupForSubstr); ok {
			g.AddSubstrMatcher(matcher, value)
			return nil
		}
	case *RegexMatcher:
		if g, ok := g.(MatcherGroupForRegex); ok {
			g.AddRegexMatcher(matcher, value)
			return nil
		}
	}
	return errors.New("cannot add matcher to matcher group")
}

// CompositeMatches flattens the matches slice to produce a single matched indices slice.
// It is designed to avoid new memory allocation as possible.
func CompositeMatches(matches [][]uint32) []uint32 {
	switch len(matches) {
	case 0:
		return nil
	case 1:
		return matches[0]
	default:
		result := make([]uint32, 0, 5)
		for i := 0; i < len(matches); i++ {
			result = append(result, matches[i]...)
		}
		return result
	}
}

// CompositeMatches flattens the matches slice to produce a single matched indices slice.
// It is designed that:
//  1. All matchers are concatenated in reverse order, so the matcher that matches further ranks higher.
//  2. Indices in the same matcher keeps their original order.
//  3. Avoid new memory allocation as possible.
func CompositeMatchesReverse(matches [][]uint32) []uint32 {
	switch len(matches) {
	case 0:
		return nil
	case 1:
		return matches[0]
	default:
		result := make([]uint32, 0, 5)
		for i := len(matches) - 1; i >= 0; i-- {
			result = append(result, matches[i]...)
		}
		return result
	}
}
