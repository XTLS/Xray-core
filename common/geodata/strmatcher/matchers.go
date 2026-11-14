package strmatcher

import (
	"errors"
	"math/bits"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"unicode"
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
	literals []string  // every match contains all of them, longest first
	tail     []byteSet // tail[i] holds the bytes a matching input can have i bytes before its end
	rest     *byteSet  // the bytes it can have further before, nil if any
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
		m.tail, m.rest = tailGuard(re)
	}
	return m, nil
}

// byteSet is a set of bytes. The bytes >= 0x80 share one bit with 0x7f.
type byteSet [4]uint32

func (s *byteSet) add(c byte)      { c = min(c, 0x7f); s[c>>5] |= 1 << (c & 31) }
func (s *byteSet) has(c byte) bool { c = min(c, 0x7f); return s[c>>5]&(1<<(c&31)) != 0 }
func (s *byteSet) or(t *byteSet) {
	for i := range s {
		s[i] |= t[i]
	}
}

var allBytes = byteSet{^uint32(0), ^uint32(0), ^uint32(0), ^uint32(0)}

// tailLen is how many positions before the end of the input tailGuard tells apart.
const tailLen = 8

// tailBudget caps how many repetition steps tailGuard walks. Only nested repeats can make the
// walk explode, so only they are charged: a flat pattern, however long, is walked once and keeps
// its guard.
const tailBudget = 100000

// tailWalk is a set of positions in the input, counted in bytes before its end.
type tailWalk struct {
	at   uint32 // bit i: exactly i bytes before the end, for i < tailLen
	far  bool   // tailLen or more bytes before the end
	free bool   // not tied to the end of the input yet
}

func (w tailWalk) union(v tailWalk) tailWalk {
	return tailWalk{w.at | v.at, w.far || v.far, w.free || v.free}
}

type tailBuilder struct {
	tail [tailLen]byteSet
	rest byteSet
	void bool
	work int
}

// tailGuard walks re backwards from the end of the input and collects the bytes an input
// matching re can have at each position before its end. It returns nil, nil when a branch
// of re does not end with $ or when nested repeats push the walk past tailBudget.
func tailGuard(re *syntax.Regexp) ([]byteSet, *byteSet) {
	var b tailBuilder
	w := b.walk(re, tailWalk{free: true})
	b.stop(w)
	if b.void {
		return nil, nil
	}
	if w.at != 0 { // a match can start here, so any bytes can come before
		for i := bits.TrailingZeros32(w.at); i < tailLen; i++ {
			b.tail[i] = allBytes
		}
	}
	if w.at != 0 || w.far {
		b.rest = allBytes
	}
	n := tailLen
	for n > 0 && b.tail[n-1] == b.rest {
		n--
	}
	var tail []byteSet
	if n > 0 {
		tail = slices.Clone(b.tail[:n])
	}
	if b.rest != allBytes {
		rest := b.rest
		return tail, &rest
	}
	return tail, nil
}

// stop ends the paths of w. One that never met $ lets its match be followed by anything.
func (b *tailBuilder) stop(w tailWalk) {
	if w.free {
		b.void = true
	}
}

func (b *tailBuilder) walk(re *syntax.Regexp, w tailWalk) tailWalk {
	if w == (tailWalk{}) || b.void {
		return w
	}
	switch re.Op {
	case syntax.OpNoMatch:
		return tailWalk{}
	case syntax.OpLiteral:
		for i := len(re.Rune) - 1; i >= 0; i-- {
			var set byteSet
			set.add(byte(min(re.Rune[i], utf8.RuneSelf)))
			if re.Flags&syntax.FoldCase != 0 {
				for f := unicode.SimpleFold(re.Rune[i]); f != re.Rune[i]; f = unicode.SimpleFold(f) {
					set.add(byte(min(f, utf8.RuneSelf)))
				}
			}
			w = b.step(w, &set)
		}
		return w
	case syntax.OpCharClass:
		var set byteSet
		for i := 0; i+1 < len(re.Rune); i += 2 {
			for r := min(re.Rune[i], utf8.RuneSelf); r <= min(re.Rune[i+1], utf8.RuneSelf); r++ {
				set.add(byte(r))
			}
		}
		return b.step(w, &set)
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL: // a domain has no \n to reject
		return b.step(w, &allBytes)
	case syntax.OpBeginText: // nothing comes before
		b.stop(w)
		return tailWalk{}
	case syntax.OpEndText:
		out := tailWalk{at: w.at & 1}
		if w.free {
			out.at = 1
		}
		return out
	case syntax.OpCapture:
		return b.walk(re.Sub[0], w)
	case syntax.OpConcat:
		for i := len(re.Sub) - 1; i >= 0; i-- {
			w = b.walk(re.Sub[i], w)
		}
		return w
	case syntax.OpAlternate:
		var out tailWalk
		for _, sub := range re.Sub {
			out = out.union(b.walk(sub, w))
		}
		return out
	case syntax.OpQuest:
		return b.repeat(re.Sub[0], w, 1)
	case syntax.OpStar:
		return b.repeat(re.Sub[0], w, -1)
	case syntax.OpPlus:
		return b.repeat(re.Sub[0], b.walk(re.Sub[0], w), -1)
	case syntax.OpRepeat:
		for i := 0; i < re.Min; i++ {
			if b.charge() {
				return w
			}
			w = b.walk(re.Sub[0], w)
		}
		if re.Max < 0 {
			return b.repeat(re.Sub[0], w, -1)
		}
		return b.repeat(re.Sub[0], w, re.Max-re.Min)
	}
	return w // empty match, line and word boundaries: no constraint
}

// charge counts one repetition step and reports whether the walk has run out of budget. Only
// repeats re-walk their body, so charging them alone bounds the blow-up of nested repeats while
// leaving a single linear pass, of any length, free.
func (b *tailBuilder) charge() bool {
	b.work++
	if b.work > tailBudget {
		b.void = true
	}
	return b.void
}

// repeat walks back over up to n more repetitions of re, any number if n < 0.
func (b *tailBuilder) repeat(re *syntax.Regexp, w tailWalk, n int) tailWalk {
	for ; n != 0; n-- {
		if b.charge() {
			return w
		}
		next := w.union(b.walk(re, w))
		if next == w {
			break
		}
		w = next
	}
	return w
}

// step walks back over one character whose last byte is in set. A character that can be
// non-ASCII can take up to 4 bytes, all >= 0x80; regexp matches an invalid byte as U+FFFD.
func (b *tailBuilder) step(w tailWalk, set *byteSet) tailWalk {
	out := tailWalk{far: w.far, free: w.free}
	if w.far {
		b.rest.or(set)
	}
	width := 1
	if set.has(0x80) {
		width = utf8.UTFMax
	}
	for i := 0; i < tailLen; i++ {
		if w.at&(1<<i) == 0 {
			continue
		}
		b.tail[i].or(set)
		for n := 1; n <= width; n++ {
			if j := i + n; j < tailLen {
				out.at |= 1 << j
				if n < width {
					b.tail[j].add(0x80)
				}
			} else {
				out.far = true
				if n < width {
					b.rest.add(0x80)
				}
			}
		}
	}
	return out
}

// mayMatch reports whether s passes the tail guard.
func (m *RegexMatcher) mayMatch(s string) bool {
	n := len(s)
	if m.rest == nil {
		n = min(n, len(m.tail))
	}
	for i := 0; i < n; i++ {
		set := m.rest
		if i < len(m.tail) {
			set = &m.tail[i]
		}
		if !set.has(s[len(s)-1-i]) {
			return false
		}
	}
	return true
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
	if !m.mayMatch(s) {
		return false
	}
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
