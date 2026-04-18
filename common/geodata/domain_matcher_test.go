package geodata

import (
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/xtls/xray-core/common/geodata/strmatcher"
)

func TestCompactDomainMatcher_PreservesCustomRuleIndices(t *testing.T) {
	factory := &CompactDomainMatcherFactory{shared: make(map[string]strmatcher.MatcherSet)}
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

	factory := &CompactDomainMatcherFactory{shared: make(map[string]strmatcher.MatcherSet)}
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
	matcher, err := (&MphDomainMatcherFactory{shared: make(map[string]strmatcher.MatcherGroup)}).BuildMatcher([]*DomainRule{
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
