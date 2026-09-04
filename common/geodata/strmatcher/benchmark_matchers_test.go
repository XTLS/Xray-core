package strmatcher_test

import (
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
