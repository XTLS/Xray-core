package strmatcher

import (
	"errors"
	"regexp"
	"regexp/syntax"
	"slices"
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
	pattern  *regexp.Regexp
	literals []string // every match contains all of them, longest first
}

func newRegexMatcher(pattern string) (Matcher, error) {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	m := &RegexMatcher{pattern: regex}
	if re, err := syntax.Parse(pattern, syntax.Perl); err == nil { // same flags as regexp.Compile
		m.literals = requiredLiterals(re, nil)
		slices.SortStableFunc(m.literals, func(a, b string) int { return len(b) - len(a) })
	}
	return m, nil
}

// requiredLiterals appends to dst the case-sensitive strings that every match of re contains.
func requiredLiterals(re *syntax.Regexp, dst []string) []string {
	switch re.Op {
	case syntax.OpLiteral:
		// regexp matches U+FFFD against invalid UTF-8 bytes, strings.Contains does not
		if re.Flags&syntax.FoldCase == 0 && !slices.Contains(re.Rune, utf8.RuneError) {
			dst = append(dst, string(re.Rune))
		}
	case syntax.OpCapture, syntax.OpPlus:
		dst = requiredLiterals(re.Sub[0], dst)
	case syntax.OpRepeat:
		if re.Min > 0 {
			dst = requiredLiterals(re.Sub[0], dst)
		}
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			dst = requiredLiterals(sub, dst)
		}
	}
	return dst
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
	for _, l := range m.literals {
		if !strings.Contains(s, l) {
			return false
		}
	}
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
		return DomainMatcher(pattern), nil
	case Regex: // 1. regex matching is case-sensitive
		return newRegexMatcher(pattern)
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
		return newRegexMatcher(pattern)
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
func CompositeMatches(matches [][]uint32) []uint32 {
	switch len(matches) {
	case 0:
		return nil
	case 1:
		return slices.Clone(matches[0])
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

// MatcherSetForAll is an interface indicating a MatcherSet could accept all types of matchers.
type MatcherSetForAll interface {
	AddMatcher(matcher Matcher)
}

// MatcherSetForFull is an interface indicating a MatcherSet could accept FullMatchers.
type MatcherSetForFull interface {
	AddFullMatcher(matcher FullMatcher)
}

// MatcherSetForDomain is an interface indicating a MatcherSet could accept DomainMatchers.
type MatcherSetForDomain interface {
	AddDomainMatcher(matcher DomainMatcher)
}

// MatcherSetForSubstr is an interface indicating a MatcherSet could accept SubstrMatchers.
type MatcherSetForSubstr interface {
	AddSubstrMatcher(matcher SubstrMatcher)
}

// MatcherSetForRegex is an interface indicating a MatcherSet could accept RegexMatchers.
type MatcherSetForRegex interface {
	AddRegexMatcher(matcher *RegexMatcher)
}

// AddMatcherToSet is a helper function to try to add a Matcher to any kind of MatcherSet.
// It returns error if the MatcherSet does not accept the provided Matcher's type.
// This function is provided to help writing code to test a MatcherSet.
func AddMatcherToSet(s MatcherSet, matcher Matcher) error {
	if s, ok := s.(IndexMatcher); ok {
		s.Add(matcher)
		return nil
	}
	if s, ok := s.(MatcherSetForAll); ok {
		s.AddMatcher(matcher)
		return nil
	}
	switch matcher := matcher.(type) {
	case FullMatcher:
		if s, ok := s.(MatcherSetForFull); ok {
			s.AddFullMatcher(matcher)
			return nil
		}
	case DomainMatcher:
		if s, ok := s.(MatcherSetForDomain); ok {
			s.AddDomainMatcher(matcher)
			return nil
		}
	case SubstrMatcher:
		if s, ok := s.(MatcherSetForSubstr); ok {
			s.AddSubstrMatcher(matcher)
			return nil
		}
	case *RegexMatcher:
		if s, ok := s.(MatcherSetForRegex); ok {
			s.AddRegexMatcher(matcher)
			return nil
		}
	}
	return errors.New("cannot add matcher to matcher set")
}
