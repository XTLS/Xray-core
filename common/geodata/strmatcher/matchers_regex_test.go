package strmatcher

import (
	"regexp"
	"slices"
	"testing"
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
	f.Fuzz(func(t *testing.T, pattern, s string) {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return
		}
		m, _ := newRegexMatcher(pattern)
		if got, want := m.Match(s), re.MatchString(s); got != want {
			t.Errorf("pattern %q, input %q: got %v, want %v", pattern, s, got, want)
		}
	})
}
