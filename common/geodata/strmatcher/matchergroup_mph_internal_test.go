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

func TestMphValueMatcherCombiner(t *testing.T) {
	build := func(matchers ...Matcher) *MphValueMatcher {
		m := NewMphValueMatcher()
		for _, x := range matchers {
			m.Add(x, 0)
		}
		if err := m.Build(); err != nil {
			t.Fatal(err)
		}
		return m
	}
	regex, err := Regex.New(`^a\d+\.net$`)
	if err != nil {
		t.Fatal(err)
	}
	saved := mphMultipliers
	t.Cleanup(func() { mphMultipliers = saved })
	mphMultipliers[0] = 1 // anagrams collide, so this one falls back to its own hash pass
	collided := build(FullMatcher("ab.com"), DomainMatcher("ba.com"))
	mphMultipliers = saved
	if collided.mph.mul == mphMultipliers[0] {
		t.Fatal("collided matcher uses the first multiplier")
	}
	matchers := []*MphValueMatcher{
		build(DomainMatcher("example.com"), FullMatcher("full.org"), DomainMatcher(".dot.io")),
		collided,
		build(regex, SubstrMatcher("keyword")),
		build(),
		build(DomainMatcher("com"), DomainMatcher("a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s")),
	}
	var s MphValueMatcherCombiner
	for i, m := range matchers {
		s.Add(m, uint32(10+i))
	}
	inputs := []string{
		"", ".", "..", "com", "example.com", "www.example.com", "xexample.com", "example.com.", "full.org", "x.full.org",
		"dot.io", "x.dot.io", ".dot.io", "ab.com", "x.ab.com", "ba.com", "x.ba.com", "a12.net", "a12.net.x", "my-keyword.org",
		"a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s", "0.a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s", "b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s",
		"x.y.z.1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17.ab.com", "x.y.z.1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17.org",
	}
	for _, input := range inputs {
		var want []uint32
		for i, m := range matchers {
			if m.MatchAny(input) {
				want = append(want, uint32(10+i))
			}
		}
		if got := s.Match(input); !slices.Equal(got, want) {
			t.Errorf("Match(%q) = %v, want %v", input, got, want)
		}
		if got := s.MatchAny(input); got != (len(want) > 0) {
			t.Errorf("MatchAny(%q) = %v", input, got)
		}
	}
	if n := testing.AllocsPerRun(100, func() { s.MatchAny("www.a.b.c.example.org") }); n != 0 {
		t.Errorf("MatchAny allocates %v times", n)
	}
}
