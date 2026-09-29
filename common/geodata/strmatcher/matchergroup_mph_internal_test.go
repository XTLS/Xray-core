package strmatcher

import (
	"slices"
	"testing"
)

func TestMphMatcherGroupHashCollision(t *testing.T) {
	saved := mphMultipliers
	defer func() { mphMultipliers = saved }()

	mphMultipliers[0] = 1 // anagrams collide
	g := NewMphMatcherGroup()
	g.AddFullMatcher(FullMatcher("ab.com"), 1)
	g.AddDomainMatcher(DomainMatcher("ba.com"), 2)
	g.AddDomainMatcher(DomainMatcher("com"), 3)
	if err := g.Build(); err != nil {
		t.Fatal(err)
	}
	if g.mul != saved[1] {
		t.Errorf("multiplier %#x, want the second one %#x", g.mul, saved[1])
	}
	for input, want := range map[string][]uint32{"ab.com": {1, 3}, "x.ba.com": {2, 3}, "x.ab.com": {3}, "ba.com": {2, 3}} {
		if m := g.Match(input); !slices.Equal(m, want) {
			t.Errorf("Match(%q) = %v, want %v", input, m, want)
		}
	}

	// Thue-Morse strings of 2048 bytes and their complements collide for every odd multiplier
	mphMultipliers = saved
	a, b := make([]byte, 2048), make([]byte, 2048)
	for i := range a {
		a[i], b[i] = "ab"[bitsOnes(i)%2], "ba"[bitsOnes(i)%2]
	}
	g = NewMphMatcherGroup()
	g.AddFullMatcher(FullMatcher(a), 1)
	g.AddFullMatcher(FullMatcher(b), 1)
	if err := g.Build(); err != errMphCollision {
		t.Errorf("Build() = %v, want %v", err, errMphCollision)
	}
}

func bitsOnes(i int) int {
	n := 0
	for ; i > 0; i &= i - 1 {
		n++
	}
	return n
}
