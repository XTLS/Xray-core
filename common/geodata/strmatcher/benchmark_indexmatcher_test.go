package strmatcher_test

import (
	"testing"

	. "github.com/xtls/xray-core/common/geodata/strmatcher"
)

func BenchmarkLinearIndexMatcher(b *testing.B) {
	benchmarkIndexMatcher(b, func() IndexMatcher {
		return NewLinearIndexMatcher()
	})
}

func BenchmarkMphIndexMatcher(b *testing.B) {
	benchmarkIndexMatcher(b, func() IndexMatcher {
		return NewMphIndexMatcher()
	})
}

func benchmarkIndexMatcher(b *testing.B, ctor func() IndexMatcher) {
	b.Run("Match", func(b *testing.B) {
		b.Run("Domain------------", func(b *testing.B) {
			benchmarkMatch(b, ctor(), map[Type]bool{Domain: true})
		})
		b.Run("Domain+Full-------", func(b *testing.B) {
			benchmarkMatch(b, ctor(), map[Type]bool{Domain: true, Full: true})
		})
		b.Run("Domain+Full+Substr", func(b *testing.B) {
			benchmarkMatch(b, ctor(), map[Type]bool{Domain: true, Full: true, Substr: true})
		})
		b.Run("All-Fail----------", func(b *testing.B) {
			benchmarkMatch(b, ctor(), map[Type]bool{Domain: false, Full: false, Substr: false})
		})
	})
	b.Run("Match/Dotless", func(b *testing.B) { // Dotless domain matcher automatically inserted in DNS app when "localhost" DNS is used.
		b.Run("All-Succ", func(b *testing.B) {
			benchmarkMatch(b, ctor(), map[Type]bool{Domain: true, Full: true, Substr: true, Regex: true})
		})
		b.Run("All-Fail", func(b *testing.B) {
			benchmarkMatch(b, ctor(), map[Type]bool{Domain: false, Full: false, Substr: false, Regex: false})
		})
	})
	b.Run("MatchAny", func(b *testing.B) {
		b.Run("First-Full--", func(b *testing.B) {
			benchmarkMatchAny(b, ctor(), map[Type]bool{Full: true, Domain: true, Substr: true})
		})
		b.Run("First-Domain", func(b *testing.B) {
			benchmarkMatchAny(b, ctor(), map[Type]bool{Full: false, Domain: true, Substr: true})
		})
		b.Run("First-Substr", func(b *testing.B) {
			benchmarkMatchAny(b, ctor(), map[Type]bool{Full: false, Domain: false, Substr: true})
		})
		b.Run("All-Fail----", func(b *testing.B) {
			benchmarkMatchAny(b, ctor(), map[Type]bool{Full: false, Domain: false, Substr: false})
		})
	})
}
