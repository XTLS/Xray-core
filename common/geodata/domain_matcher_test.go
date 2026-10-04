package geodata

import (
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/geodata/strmatcher"
	"github.com/xtls/xray-core/common/utils"
)

func TestCompactDomainMatcher_PreservesCustomRuleIndices(t *testing.T) {
	factory := &CompactMphDomainMatcherFactory{shared: utils.NewWeakCacheMap[string, strmatcher.MphValueMatcher]()}
	matcher, err := factory.BuildMatcher([]*DomainRule{
		{Value: &DomainRule_Custom{Custom: &Domain{Type: Domain_Full, Value: "example.com"}}},
		{Value: &DomainRule_Custom{Custom: &Domain{Type: Domain_Domain, Value: "example.com"}}},
	})
	if err != nil {
		t.Fatalf("BuildMatcher() failed: %v", err)
	}

	got := matcher.Match("example.com")
	slices.Sort(got)

	want := []uint32{0, 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Match() = %v, want %v", got, want)
	}
}

func TestCompactDomainMatcher_PreservesMixedRuleIndices(t *testing.T) {
	t.Setenv("xray.location.asset", filepath.Join("..", "..", "resources"))

	factory := &CompactMphDomainMatcherFactory{shared: utils.NewWeakCacheMap[string, strmatcher.MphValueMatcher]()}
	matcher, err := factory.BuildMatcher([]*DomainRule{
		{Value: &DomainRule_Geosite{Geosite: &GeoSiteRule{File: DefaultGeoSiteDat, Code: "CN"}}},
		{Value: &DomainRule_Custom{Custom: &Domain{Type: Domain_Full, Value: "163.com"}}},
	})
	if err != nil {
		t.Fatalf("BuildMatcher() failed: %v", err)
	}

	got := matcher.Match("163.com")
	slices.Sort(got)

	want := []uint32{0, 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Match() = %v, want %v", got, want)
	}
}

func TestMphDomainMatcher_MatchReturnsDetachedSlice(t *testing.T) {
	matcher, err := (&MphDomainMatcherFactory{shared: utils.NewWeakCacheMap[string, strmatcher.MphValueMatcher]()}).
		BuildMatcher([]*DomainRule{
			{Value: &DomainRule_Custom{Custom: &Domain{Type: Domain_Full, Value: "example.com"}}},
			{Value: &DomainRule_Custom{Custom: &Domain{Type: Domain_Domain, Value: "example.com"}}},
		})
	if err != nil {
		t.Fatalf("BuildMatcher() failed: %v", err)
	}

	got := matcher.Match("example.com")
	if !reflect.DeepEqual(got, []uint32{0, 1}) {
		t.Fatalf("Match() = %v, want %v", got, []uint32{0, 1})
	}

	got[0] = 1

	gotAgain := matcher.Match("example.com")
	if !reflect.DeepEqual(gotAgain, []uint32{0, 1}) {
		t.Fatalf("Match() after caller mutation = %v, want %v", gotAgain, []uint32{0, 1})
	}
}

// DNS sorts every Match result in place, so a matcher must never hand out a
// slice it keeps, also when only its keyword or regex part matches.
func TestDomainMatcher_MatchResultsCanBeSortedConcurrently(t *testing.T) {
	t.Setenv("xray.location.asset", filepath.Join("..", "..", "resources"))

	rules := []*DomainRule{
		{Value: &DomainRule_Custom{Custom: &Domain{Type: Domain_Full, Value: "example.com"}}},
		{Value: &DomainRule_Custom{Custom: &Domain{Type: Domain_Domain, Value: "example.com"}}},
		{Value: &DomainRule_Custom{Custom: &Domain{Type: Domain_Substr, Value: "exam"}}},
		{Value: &DomainRule_Custom{Custom: &Domain{Type: Domain_Regex, Value: `^ex.*\.org$`}}},
		{Value: &DomainRule_Custom{Custom: &Domain{Type: Domain_Substr, Value: "exam"}}},
		{Value: &DomainRule_Geosite{Geosite: &GeoSiteRule{File: DefaultGeoSiteDat, Code: "CN"}}},
		{Value: &DomainRule_Custom{Custom: &Domain{Type: Domain_Full, Value: "only.full.test"}}},
	}
	cases := []struct {
		input string
		want  []uint32
	}{
		{"example.com", []uint32{0, 1, 2, 4}},
		{"www.example.com", []uint32{1, 2, 4}},
		{"exam.net", []uint32{2, 4}}, // keyword part only
		{"example.org", []uint32{2, 3, 4}},
		{"163.com", []uint32{5}},
		{"www.163.com", []uint32{5}},
		{"only.full.test", []uint32{6}}, // full part only
		{"nomatch.test", nil},
	}
	factories := map[string]DomainMatcherFactory{
		"mph":     &MphDomainMatcherFactory{shared: utils.NewWeakCacheMap[string, strmatcher.MphValueMatcher]()},
		"compact": &CompactMphDomainMatcherFactory{shared: utils.NewWeakCacheMap[string, strmatcher.MphValueMatcher]()},
	}
	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			matcher, err := factory.BuildMatcher(rules)
			if err != nil {
				t.Fatalf("BuildMatcher() failed: %v", err)
			}
			for _, c := range cases {
				got := matcher.Match(c.input)
				if sorted := slices.Sorted(slices.Values(got)); !slices.Equal(sorted, c.want) {
					t.Fatalf("Match(%q) = %v, want %v", c.input, sorted, c.want)
				}
				got = got[:cap(got)]
				for j := range got {
					got[j] = ^uint32(0)
				}
				if again := slices.Sorted(slices.Values(matcher.Match(c.input))); !slices.Equal(again, c.want) {
					t.Fatalf("Match(%q) after caller mutation = %v, want %v", c.input, again, c.want)
				}
			}

			var wg sync.WaitGroup
			for range 8 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for range 500 {
						for _, c := range cases {
							got := matcher.Match(c.input)
							slices.Sort(got)
							if !slices.Equal(got, c.want) {
								t.Errorf("Match(%q) = %v, want %v", c.input, got, c.want)
								return
							}
						}
					}
				}()
			}
			wg.Wait()
		})
	}
}
