package geodata

import (
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/xtls/xray-core/common/geodata/strmatcher"
)

func TestCompactDomainMatcher_PreservesCustomRuleIndices(t *testing.T) {
	factory := &CompactDomainMatcherFactory{shared: make(map[string]strmatcher.MatcherGroup)}
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

	factory := &CompactDomainMatcherFactory{shared: make(map[string]strmatcher.MatcherGroup)}
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
