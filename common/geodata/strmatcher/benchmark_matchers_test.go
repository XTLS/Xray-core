package strmatcher_test

import (
	"regexp"
	"strconv"
	"testing"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/geodata/strmatcher"
)

func BenchmarkFullMatcher(b *testing.B) {
	b.Run("SimpleMatcherGroup------", func(b *testing.B) {
		benchmarkMatcherType(b, Full, func() MatcherGroup {
			return new(SimpleMatcherGroup)
		})
	})
	b.Run("FullMatcherGroup--------", func(b *testing.B) {
		benchmarkMatcherType(b, Full, func() MatcherGroup {
			return NewFullMatcherGroup()
		})
	})
	b.Run("ACAutomationMatcherGroup", func(b *testing.B) {
		benchmarkMatcherType(b, Full, func() MatcherGroup {
			return NewACAutomatonMatcherGroup()
		})
	})
	b.Run("MphMatcherGroup---------", func(b *testing.B) {
		benchmarkMatcherType(b, Full, func() MatcherGroup {
			return NewMphMatcherGroup()
		})
	})
}

func BenchmarkDomainMatcher(b *testing.B) {
	b.Run("SimpleMatcherGroup------", func(b *testing.B) {
		benchmarkMatcherType(b, Domain, func() MatcherGroup {
			return new(SimpleMatcherGroup)
		})
	})
	b.Run("DomainMatcherGroup------", func(b *testing.B) {
		benchmarkMatcherType(b, Domain, func() MatcherGroup {
			return NewDomainMatcherGroup()
		})
	})
	b.Run("ACAutomationMatcherGroup", func(b *testing.B) {
		benchmarkMatcherType(b, Domain, func() MatcherGroup {
			return NewACAutomatonMatcherGroup()
		})
	})
	b.Run("MphMatcherGroup---------", func(b *testing.B) {
		benchmarkMatcherType(b, Domain, func() MatcherGroup {
			return NewMphMatcherGroup()
		})
	})
}

func BenchmarkSubstrMatcher(b *testing.B) {
	b.Run("SimpleMatcherGroup------", func(b *testing.B) {
		benchmarkMatcherType(b, Substr, func() MatcherGroup {
			return new(SimpleMatcherGroup)
		})
	})
	b.Run("SubstrMatcherGroup------", func(b *testing.B) {
		benchmarkMatcherType(b, Substr, func() MatcherGroup {
			return new(SubstrMatcherGroup)
		})
	})
	b.Run("ACAutomationMatcherGroup", func(b *testing.B) {
		benchmarkMatcherType(b, Substr, func() MatcherGroup {
			return NewACAutomatonMatcherGroup()
		})
	})
}

func BenchmarkRegexMatcher(b *testing.B) {
	patterns := []string{ // taken from geosite
		`(^|\.)91porn\.(best|com|cool|fun|group|party|plus|site|tw|work)$`,
		`(^|\.)91porn[0-9]{3}\.me$`,
		`(^|\.)apiproxy-device-prod-nlb-.+\.amazonaws\.com$`,
		`(^|\.)dualstack\.apiproxy-.+\.amazonaws\.com$`,
		`(^|\.)aqdk[0-9]{3}\.com$`,
		`(^|\.)bilibili3(0[1-9]|1[0-2])\.xyz$`,
		`(^|\.)byyum([3589]|2[235689]|3[34]|4[1-9]|5[1-79]|6[0134679])?\.com$`,
		`(^|\.)fiftymvapi\..+$`,
		`(^|\.)gossipfuli[0-9]{3,4}\.xyz$`,
		`(^|\.)kpkuang\.(bond|fun|info|one|us)$`,
		`(^|\.)rule34\.(asia|us|world|xxx|xyz)$`,
		`(^|\.)[a-z][1-9][0-9][a-z]\.com$`,
		`.+\.awsdns-[0-9][0-9]\.(co\.uk|com|net|org)$`,
		`.+\.dkr\.ecr\.[^\.]+\.amazonaws\.com$`,
		`^(.+\.)*zh\.okaapps\.com$`,
		`^cdn\d-epicgames-\d+\.file\.myqcloud\.com$`,
		`^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$`,
		`^r+[0-9]+(---|\.)sn-(2x3|ni5|j5o)\w{5}\.googlevideo\.com$`,
		`^speed\.(coe|open)\.ad\.[a-z]{2,6}\.prod\.hosts\.ooklaserver\.net$`,
		`javdb\d+\.com$`,
	}
	domains := []string{
		"www.google.com", "rr3---sn-4g5edndy.googlevideo.com", "r1---sn-2x3abcde.googlevideo.com", "i.ytimg.com",
		"graph.facebook.com", "api.twitter.com", "www.baidu.com", "github.com", "objects.githubusercontent.com",
		"login.microsoftonline.com", "e1234.dscb.akamaiedge.net", "d1a2b3c4d5e6f7.cloudfront.net",
		"s3.us-east-1.amazonaws.com", "123456789012.dkr.ecr.us-east-1.amazonaws.com", "www.wikipedia.org",
		"discord.com", "telegram.org", "store.steampowered.com", "www.91porn.com", "ns-1234.awsdns-12.org",
	}
	bench := func(b *testing.B, ctor func(pattern string) func(string) bool) {
		var matchers []func(string) bool
		for _, p := range patterns {
			matchers = append(matchers, ctor(p))
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for _, d := range domains {
				for _, match := range matchers {
					_ = match(d)
				}
			}
		}
	}
	b.Run("regexp", func(b *testing.B) {
		bench(b, func(pattern string) func(string) bool {
			return regexp.MustCompile(pattern).MatchString
		})
	})
	b.Run("prefilter", func(b *testing.B) {
		bench(b, func(pattern string) func(string) bool {
			m, err := Regex.New(pattern)
			common.Must(err)
			return m.Match
		})
	})
}

// Utility functions for benchmark

func benchmarkMatcherType(b *testing.B, t Type, ctor func() MatcherGroup) {
	b.Run("Match", func(b *testing.B) {
		b.Run("Succ", func(b *testing.B) {
			benchmarkMatch(b, ctor(), map[Type]bool{t: true})
		})
		b.Run("Fail", func(b *testing.B) {
			benchmarkMatch(b, ctor(), map[Type]bool{t: false})
		})
	})
	b.Run("MatchAny", func(b *testing.B) {
		b.Run("Succ", func(b *testing.B) {
			benchmarkMatchAny(b, ctor(), map[Type]bool{t: true})
		})
		b.Run("Fail", func(b *testing.B) {
			benchmarkMatchAny(b, ctor(), map[Type]bool{t: false})
		})
	})
}

func benchmarkMatch(b *testing.B, g MatcherGroup, enabledTypes map[Type]bool) {
	prepareMatchers(g, enabledTypes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = g.Match("0.example.com")
	}
}

func benchmarkMatchAny(b *testing.B, g MatcherGroup, enabledTypes map[Type]bool) {
	prepareMatchers(g, enabledTypes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = g.MatchAny("0.example.com")
	}
}

func prepareMatchers(g MatcherGroup, enabledTypes map[Type]bool) {
	for matcherType, hasMatch := range enabledTypes {
		switch matcherType {
		case Domain:
			if hasMatch {
				AddMatcherToGroup(g, DomainMatcher("example.com"), 0)
			}
			for i := 1; i < 1024; i++ {
				AddMatcherToGroup(g, DomainMatcher(strconv.Itoa(i)+".example.com"), uint32(i))
			}
		case Full:
			if hasMatch {
				AddMatcherToGroup(g, FullMatcher("0.example.com"), 0)
			}
			for i := 1; i < 64; i++ {
				AddMatcherToGroup(g, FullMatcher(strconv.Itoa(i)+".example.com"), uint32(i))
			}
		case Substr:
			if hasMatch {
				AddMatcherToGroup(g, SubstrMatcher("example.com"), 0)
			}
			for i := 1; i < 4; i++ {
				AddMatcherToGroup(g, SubstrMatcher(strconv.Itoa(i)+".example.com"), uint32(i))
			}
		case Regex:
			matcher, err := Regex.New("^[^.]*$") // Dotless domain matcher automatically inserted in DNS app when "localhost" DNS is used.
			common.Must(err)
			AddMatcherToGroup(g, matcher, 0)
		}
	}
	if g, ok := g.(buildable); ok {
		common.Must(g.Build())
	}
}

type buildable interface {
	Build() error
}
