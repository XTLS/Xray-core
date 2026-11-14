package strmatcher

import (
	"hash/fnv"
	"math/rand/v2"
	"regexp"
	"regexp/syntax"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

var regexLiteralCases = []struct {
	pattern  string
	literals []string
}{
	{`(^|\.)91porn\.(best|com)$`, []string{"91porn."}},
	{`.+\.awsdns-cn-[0-9][0-9]\.(biz|com|net|top)$`, []string{".awsdns-cn-", "."}},
	{`^r+[0-9]+(---|\.)sn-(2x3|ni5|j5o)\w{5}\.googlevideo\.com$`, []string{".googlevideo.com", "sn-", "r"}},
	{`(?i)abc`, nil},
	{`ab(?i:CD)ef`, []string{"ab", "ef"}},
	{`(abc)?x`, []string{"x"}},
	{`(abc)*x`, []string{"x"}},
	{`x{0,3}yy`, []string{"yy"}},
	{`(ab)+c{2}`, []string{"ab", "c"}},
	{`abc|abd`, []string{"ab"}},
	{`\Qa.b\E`, []string{"a.b"}},
	{`a\x{FFFD}b`, nil},
	{`^[^.]+$`, nil},
}

func TestRegexRequiredLiterals(t *testing.T) {
	for _, test := range regexLiteralCases {
		m, err := newRegexMatcher(test.pattern)
		if err != nil {
			t.Fatal(err)
		}
		if got := m.(*RegexMatcher).literals; !slices.Equal(got, test.literals) {
			t.Errorf("%s: got %q, want %q", test.pattern, got, test.literals)
		}
	}
}

var regexTailCases = []struct {
	pattern string
	guard   bool
	match   []string // inputs the pattern matches
	reject  []string // inputs the tail guard alone rejects
}{
	{`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`, true, []string{"a", "localhost", "x-1"}, []string{"www.example.com", "localhost.", "LOCALHOST", "a b"}},
	{`(^|\.)[a-z][1-9][0-9][a-z]\.com$`, true, []string{"a12b.com", "x.q10z.com"}, []string{"google.com", "a12b.co", "a12b.com.", "ab12.com"}},
	{`^hses[1-7]?\.akamaized\.net$`, true, []string{"hses.akamaized.net", "hses3.akamaized.net"}, []string{"xhses.akamaized.net", "www.hses.akamaized.net"}},
	{`(?i)k\.net$`, true, []string{"k.net", "K.NET", "\u212a.net"}, []string{"x.net", "k.nex"}},
	{`[^.]+\.cn$`, true, []string{"a.cn", "\xff.cn", "\u4e2d.cn"}, []string{"a.cnn", "a.c"}},
	{`\x{FFFD}$`, true, []string{"\xff", "a\xc3", "\uFFFD"}, []string{"a", "\xff."}},
	{`^.\.cn$`, true, []string{"a.cn", "\u4E2D.cn", "\xff.cn"}, []string{"ab.cn"}},
	{`^$`, true, []string{""}, []string{"a"}},
	{`(^|\.)youyuapi\..+$`, false, []string{"youyuapi.com"}, nil},
	{`abc`, false, []string{"abc", "xabcx"}, nil},
	{`^ab`, false, []string{"ab", "abc"}, nil},
	{`a$|b`, false, []string{"a", "bx"}, nil},
	{`(?m)a$`, false, []string{"a", "a\nb"}, nil},
	{strings.Repeat(`(?:abcdefgh(?:a`, 20) + strings.Repeat(`)*)*`, 20) + `\.com$`, false, []string{".com", "abcdefgha.com"}, nil}, // over tailBudget
}

func TestRegexTailGuard(t *testing.T) {
	for _, test := range regexTailCases {
		m, err := newRegexMatcher(test.pattern)
		if err != nil {
			t.Fatal(err)
		}
		rm := m.(*RegexMatcher)
		if guard := rm.tail != nil || rm.rest != nil; guard != test.guard {
			t.Errorf("%s: guard %v, want %v", test.pattern, guard, test.guard)
		}
		for _, s := range test.match {
			if !rm.pattern.MatchString(s) || !rm.Match(s) {
				t.Errorf("%s: %q does not match", test.pattern, s)
			}
		}
		for _, s := range test.reject {
			if rm.pattern.MatchString(s) || rm.mayMatch(s) {
				t.Errorf("%s: %q passes the guard", test.pattern, s)
			}
		}
	}
}

// TestRegexTailGuardFlatAlternation checks that a long but non-recursive pattern keeps its
// guard. Only nested repeats are charged against tailBudget, so a flat alternation of many
// names, however large, is walked once and guarded; its guard is checked against regexp.
func TestRegexTailGuardFlatAlternation(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("(?:")
	for i := 0; i < 20000; i++ {
		if i > 0 {
			sb.WriteByte('|')
		}
		sb.WriteString("name")
		sb.WriteString(strconv.Itoa(i))
	}
	sb.WriteString(`)\.example\.com$`)
	m, err := newRegexMatcher(sb.String())
	if err != nil {
		t.Fatal(err)
	}
	rm := m.(*RegexMatcher)
	if rm.tail == nil && rm.rest == nil {
		t.Fatal("flat alternation of 20000 names lost its guard")
	}
	for _, s := range []string{"name0.example.com", "name19999.example.com", "x.name12345.example.com"} {
		if !rm.pattern.MatchString(s) || !rm.Match(s) {
			t.Errorf("%q should match", s)
		}
	}
	for _, s := range []string{"name0.example.org", "name0.example.com.", "name0.example.con", "google.com"} {
		if rm.pattern.MatchString(s) {
			t.Fatalf("test bug: %q matches the pattern", s)
		}
		if rm.mayMatch(s) {
			t.Errorf("%q should be rejected by the guard", s)
		}
	}
}

// sampleMatch appends a string that re matches, assertions aside, unless it runs out of
// budget, which it spends one per call so that nested repeats stay cheap.
func sampleMatch(sb *strings.Builder, re *syntax.Regexp, rnd *rand.Rand, budget *int) {
	if *budget <= 0 {
		return
	}
	*budget--
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if re.Flags&syntax.FoldCase != 0 {
				for n := rnd.IntN(4); n > 0; n-- {
					r = unicode.SimpleFold(r)
				}
			}
			sampleRune(sb, r, rnd)
		}
	case syntax.OpCharClass:
		if len(re.Rune) > 0 {
			i := rnd.IntN(len(re.Rune)/2) * 2
			sampleRune(sb, re.Rune[i]+rnd.Int32N(min(re.Rune[i+1]-re.Rune[i]+1, 300)), rnd)
		}
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		sampleRune(sb, []rune{'a', '.', '\n', 0xe9, 0x212a, utf8.RuneError}[rnd.IntN(6)], rnd)
	case syntax.OpCapture:
		sampleMatch(sb, re.Sub[0], rnd, budget)
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			sampleMatch(sb, sub, rnd, budget)
		}
	case syntax.OpAlternate:
		sampleMatch(sb, re.Sub[rnd.IntN(len(re.Sub))], rnd, budget)
	case syntax.OpQuest, syntax.OpStar, syntax.OpPlus, syntax.OpRepeat:
		lo, hi := 0, 3
		switch re.Op {
		case syntax.OpQuest:
			hi = 1
		case syntax.OpPlus:
			lo = 1
		case syntax.OpRepeat:
			lo, hi = re.Min, re.Min+3
			if re.Max >= 0 {
				hi = min(hi, re.Max)
			}
		}
		for n := lo + rnd.IntN(hi-lo+1); n > 0; n-- {
			sampleMatch(sb, re.Sub[0], rnd, budget)
		}
	}
}

func sampleRune(sb *strings.Builder, r rune, rnd *rand.Rand) {
	if r == utf8.RuneError && rnd.IntN(2) == 0 {
		sb.WriteByte(0x80 | byte(rnd.IntN(0x80))) // regexp matches an invalid byte as U+FFFD
		return
	}
	sb.WriteRune(r)
}

func FuzzRegexMatcher(f *testing.F) {
	inputs := []string{
		"", "x", "yy", "abd", "ccc", "ABC", "abCDef", "abcdef", "abababcc", "a.b", "a\xffb", "a\uFFFDb",
		"www.91porn.com", "ns1.awsdns-cn-01.top", "r1---sn-2x3abcde.googlevideo.com",
	}
	for _, test := range regexLiteralCases {
		for _, s := range inputs {
			f.Add(test.pattern, s)
		}
	}
	for _, test := range regexTailCases {
		for _, s := range append(test.match, test.reject...) {
			f.Add(test.pattern, s)
		}
	}
	f.Fuzz(func(t *testing.T, pattern, s string) {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return
		}
		m, _ := newRegexMatcher(pattern)
		check := func(s string) {
			if got, want := m.Match(s), re.MatchString(s); got != want {
				t.Errorf("pattern %q, input %q: got %v, want %v", pattern, s, got, want)
			}
		}
		check(s)
		// random inputs seldom match, so also try strings built from the pattern
		parsed, _ := syntax.Parse(pattern, syntax.Perl)
		h := fnv.New64a()
		h.Write([]byte(s))
		rnd := rand.New(rand.NewPCG(h.Sum64(), 1))
		for range 8 {
			var sb strings.Builder
			budget := 256
			sampleMatch(&sb, parsed, rnd, &budget)
			sample := sb.String()
			check(sample)
			check(s + sample)
			if len(sample) > 0 && len(s) > 0 {
				i := rnd.IntN(len(sample))
				check(sample[:i] + s[:1] + sample[i+1:])
			}
		}
	})
}
