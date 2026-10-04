package strmatcher_test

import (
	"math/rand"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/geodata/strmatcher"
)

func TestMphMatcherGroup(t *testing.T) {
	cases1 := []struct {
		pattern string
		mType   Type
		input   string
		output  bool
	}{
		{
			pattern: "example.com",
			mType:   Domain,
			input:   "www.example.com",
			output:  true,
		},
		{
			pattern: "example.com",
			mType:   Domain,
			input:   "example.com",
			output:  true,
		},
		{
			pattern: "example.com",
			mType:   Domain,
			input:   "www.e3ample.com",
			output:  false,
		},
		{
			pattern: "example.com",
			mType:   Domain,
			input:   "xample.com",
			output:  false,
		},
		{
			pattern: "example.com",
			mType:   Domain,
			input:   "xexample.com",
			output:  false,
		},
		{
			pattern: "example.com",
			mType:   Full,
			input:   "example.com",
			output:  true,
		},
		{
			pattern: "example.com",
			mType:   Full,
			input:   "xexample.com",
			output:  false,
		},
	}
	for _, test := range cases1 {
		mph := NewMphMatcherGroup()
		matcher, err := test.mType.New(test.pattern)
		common.Must(err)
		common.Must(AddMatcherToGroup(mph, matcher, 0))
		mph.Build()
		if m := mph.MatchAny(test.input); m != test.output {
			t.Error("unexpected output: ", m, " for test case ", test)
		}
	}
	{
		cases2Input := []struct {
			pattern string
			mType   Type
		}{
			{
				pattern: "163.com",
				mType:   Domain,
			},
			{
				pattern: "m.126.com",
				mType:   Full,
			},
			{
				pattern: "3.com",
				mType:   Full,
			},
		}
		mph := NewMphMatcherGroup()
		for _, test := range cases2Input {
			matcher, err := test.mType.New(test.pattern)
			common.Must(err)
			common.Must(AddMatcherToGroup(mph, matcher, 0))
		}
		mph.Build()
		cases2Output := []struct {
			pattern string
			res     bool
		}{
			{
				pattern: "126.com",
				res:     false,
			},
			{
				pattern: "m.163.com",
				res:     true,
			},
			{
				pattern: "mm163.com",
				res:     false,
			},
			{
				pattern: "m.126.com",
				res:     true,
			},
			{
				pattern: "163.com",
				res:     true,
			},
			{
				pattern: "63.com",
				res:     false,
			},
			{
				pattern: "oogle.com",
				res:     false,
			},
			{
				pattern: "vvgoogle.com",
				res:     false,
			},
		}
		for _, test := range cases2Output {
			if m := mph.MatchAny(test.pattern); m != test.res {
				t.Error("unexpected output: ", m, " for test case ", test)
			}
		}
	}
	{
		cases3Input := []struct {
			pattern string
			mType   Type
		}{
			{
				pattern: "video.google.com",
				mType:   Domain,
			},
			{
				pattern: "gle.com",
				mType:   Domain,
			},
		}
		mph := NewMphMatcherGroup()
		for _, test := range cases3Input {
			matcher, err := test.mType.New(test.pattern)
			common.Must(err)
			common.Must(AddMatcherToGroup(mph, matcher, 0))
		}
		mph.Build()
		cases3Output := []struct {
			pattern string
			res     bool
		}{
			{
				pattern: "google.com",
				res:     false,
			},
		}
		for _, test := range cases3Output {
			if m := mph.MatchAny(test.pattern); m != test.res {
				t.Error("unexpected output: ", m, " for test case ", test)
			}
		}
	}
}

// See https://github.com/v2fly/v2ray-core/issues/92#issuecomment-673238489
func TestMphMatcherGroupAsIndexMatcher(t *testing.T) {
	rules := []struct {
		Type   Type
		Domain string
	}{
		// Regex not supported by MphMatcherGroup
		// {
		// 	Type:   Regex,
		// 	Domain: "apis\\.us$",
		// },
		// Substr not supported by MphMatcherGroup
		// {
		// 	Type:   Substr,
		// 	Domain: "apis",
		// },
		{
			Type:   Domain,
			Domain: "googleapis.com",
		},
		{
			Type:   Domain,
			Domain: "com",
		},
		{
			Type:   Full,
			Domain: "www.baidu.com",
		},
		// Substr not supported by MphMatcherGroup, We add another matcher to preserve index
		{
			Type:   Domain,        // Substr,
			Domain: "example.com", // "apis",
		},
		{
			Type:   Domain,
			Domain: "googleapis.com",
		},
		{
			Type:   Full,
			Domain: "fonts.googleapis.com",
		},
		{
			Type:   Full,
			Domain: "www.baidu.com",
		},
		{ // This matcher (index 10) is swapped with matcher (index 6) to test that full matcher takes high priority.
			Type:   Full,
			Domain: "example.com",
		},
		{
			Type:   Domain,
			Domain: "example.com",
		},
	}
	cases := []struct {
		Input  string
		Output []uint32
	}{
		{
			Input:  "www.baidu.com",
			Output: []uint32{5, 9, 4},
		},
		{
			Input:  "fonts.googleapis.com",
			Output: []uint32{8, 3, 7, 4 /*2, 6*/},
		},
		{
			Input:  "example.googleapis.com",
			Output: []uint32{3, 7, 4 /*2, 6*/},
		},
		{
			Input: "testapis.us",
			// Output: []uint32{ /*2, 6*/ /*1,*/ },
			Output: nil,
		},
		{
			Input:  "example.com",
			Output: []uint32{10, 6, 11, 4},
		},
	}
	matcherGroup := NewMphMatcherGroup()
	for i, rule := range rules {
		matcher, err := rule.Type.New(rule.Domain)
		common.Must(err)
		common.Must(AddMatcherToGroup(matcherGroup, matcher, uint32(i+3)))
	}
	matcherGroup.Build()
	for _, test := range cases {
		if m := matcherGroup.Match(test.Input); !reflect.DeepEqual(m, test.Output) {
			t.Error("unexpected output: ", m, " for test case ", test)
		}
	}
}

func TestEmptyMphMatcherGroup(t *testing.T) {
	g := NewMphMatcherGroup()
	g.Build()
	r := g.Match("example.com")
	if len(r) != 0 {
		t.Error("Expect [], but ", r)
	}
}

func TestMphMatcherGroupRandom(t *testing.T) {
	inputs := []string{""} // All strings over "ab." up to 7 bytes
	for i := 0; len(inputs[i]) < 7; i++ {
		for _, c := range []string{"a", "b", "."} {
			inputs = append(inputs, inputs[i]+c)
		}
	}
	for seed := int64(0); seed < 300; seed++ {
		r := rand.New(rand.NewSource(seed))
		g := NewMphMatcherGroup()
		full, domain := map[string][]uint32{}, map[string][]uint32{} // Stored pattern -> values
		for value := uint32(r.Intn(200)); value > 0; value-- {
			pattern := make([]byte, r.Intn(8))
			for i := range pattern {
				pattern[i] = "ab."[r.Intn(3)]
			}
			if p := string(pattern); r.Intn(2) == 0 {
				g.AddFullMatcher(FullMatcher(p), value)
				full[p] = append(full[p], value)
			} else {
				g.AddDomainMatcher(DomainMatcher(p), value)
				domain[p] = append(domain[p], value)
				domain["."+p] = append(domain["."+p], value)
			}
		}
		common.Must(g.Build())
		for _, input := range inputs {
			keys := []string{input} // Whole input first, then "." suffixes from longest to shortest
			for i := range len(input) {
				if input[i] == '.' {
					keys = append(keys, input[i:])
				}
			}
			var want []uint32
			for _, k := range keys {
				want = append(append(want, full[k]...), domain[k]...)
			}
			// Compared as sets: Match reports a value once per matching pattern, and orders them differently
			// from want for patterns and inputs with a leading dot
			m := g.Match(input)
			if !slices.Equal(sortedSet(m), sortedSet(want)) {
				t.Fatalf("seed %d: Match(%q) = %v, want %v", seed, input, m, want)
			}
			if m := g.MatchAny(input); m != (len(want) > 0) {
				t.Fatalf("seed %d: MatchAny(%q) = %v", seed, input, m)
			}
		}
	}
}

func TestMphMatcherGroupAppend(t *testing.T) {
	g := NewMphMatcherGroup()
	g.AddFullMatcher(FullMatcher("a.com"), 1)
	g.AddFullMatcher(FullMatcher("b.com"), 2)
	g.Build()
	if m := append(g.Match("a.com"), 3); !slices.Equal(m, []uint32{1, 3}) {
		t.Error("expect [1 3], but ", m)
	}
	if m := g.Match("b.com"); !slices.Equal(m, []uint32{2}) {
		t.Error("expect [2], but ", m)
	}
}

func sortedSet(v []uint32) []uint32 {
	v = slices.Clone(v)
	slices.Sort(v)
	return slices.Compact(v)
}

func TestMphMatcherGroupLongPattern(t *testing.T) {
	long := strings.Repeat("a", 300) + ".com"
	for _, values := range [][4]uint32{{1, 2, 3, 4}, {7, 7, 7, 7}} {
		g := NewMphMatcherGroup()
		g.AddDomainMatcher(DomainMatcher(long), values[0])
		g.AddFullMatcher(FullMatcher("x."+long), values[1])
		g.AddFullMatcher(FullMatcher(long[:255]), values[2]) // the shortest pattern stored with a long length
		g.AddFullMatcher(FullMatcher(long[:254]), values[3])
		common.Must(g.Build())
		cases := []struct {
			input string
			want  []uint32
		}{
			{long, []uint32{values[0]}},
			{"www." + long, []uint32{values[0]}},
			{"x." + long, []uint32{values[1], values[0]}},
			{long[1:], nil},
			{"a" + long, nil},
			{long[:255], []uint32{values[2]}},
			{long[:254], []uint32{values[3]}},
			{long[:256], nil},
			{long[:253], nil},
		}
		for _, c := range cases {
			if m := g.Match(c.input); !slices.Equal(m, c.want) {
				t.Errorf("Match(%d bytes) = %v, want %v", len(c.input), m, c.want)
			}
			if m := g.MatchAny(c.input); m != (c.want != nil) {
				t.Errorf("MatchAny(%d bytes) = %v", len(c.input), m)
			}
		}
	}

	// A pattern longer than 65535 bytes builds and matches: a record's length is a uvarint,
	// so the only cap was the build-time length field, now widened to uint32.
	huge := strings.Repeat("a", 70000)
	g := NewMphMatcherGroup()
	g.AddFullMatcher(FullMatcher(strings.Repeat("a", 65535)), 1)
	g.AddDomainMatcher(DomainMatcher(huge+".com"), 2)
	g.AddFullMatcher(FullMatcher("a.com"), 3)
	common.Must(g.Build())
	if !g.MatchAny(strings.Repeat("a", 65535)) || g.MatchAny(strings.Repeat("a", 65534)) {
		t.Error("wrong answer for a 65535-byte pattern")
	}
	if m := g.Match(huge + ".com"); !slices.Equal(m, []uint32{2}) {
		t.Errorf("Match(%d-byte input) = %v, want [2]", len(huge)+4, m)
	}
	if m := g.Match("x." + huge + ".com"); !slices.Equal(m, []uint32{2}) {
		t.Errorf("Match(subdomain of a %d-byte pattern) = %v, want [2]", len(huge)+4, m)
	}
	if g.MatchAny(huge) { // the 70000-byte label on its own is not a rule
		t.Error("unexpected match for the bare 70000-byte label")
	}
}

func TestMphMatcherGroupBuildOnce(t *testing.T) {
	g := NewMphMatcherGroup()
	g.AddFullMatcher(FullMatcher("a.com"), 1)
	common.Must(g.Build())
	if err := g.Build(); err == nil || !g.MatchAny("a.com") {
		t.Errorf("second Build() = %v, MatchAny(a.com) = %v", err, g.MatchAny("a.com"))
	}
	defer func() {
		if recover() == nil {
			t.Error("Add after Build did not panic")
		}
	}()
	g.AddDomainMatcher(DomainMatcher("b.com"), 2)
}
