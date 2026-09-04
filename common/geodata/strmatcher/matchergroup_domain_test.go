package strmatcher_test

import (
	"reflect"
	"testing"

	. "github.com/xtls/xray-core/common/geodata/strmatcher"
)

func TestDomainMatcherGroup(t *testing.T) {
	patterns := []struct {
		Pattern string
		Value   uint32
	}{
		{
			Pattern: "example.com",
			Value:   1,
		},
		{
			Pattern: "google.com",
			Value:   2,
		},
		{
			Pattern: "x.a.com",
			Value:   3,
		},
		{
			Pattern: "a.b.com",
			Value:   4,
		},
		{
			Pattern: "c.a.b.com",
			Value:   5,
		},
		{
			Pattern: "x.y.com",
			Value:   4,
		},
		{
			Pattern: "x.y.com",
			Value:   6,
		},
	}
	testCases := []struct {
		Domain string
		Result []uint32
	}{
		{
			Domain: "x.example.com",
			Result: []uint32{1},
		},
		{
			Domain: "y.com",
			Result: nil,
		},
		{
			Domain: "a.b.com",
			Result: []uint32{4},
		},
		{ // Matches [c.a.b.com, a.b.com]
			Domain: "c.a.b.com",
			Result: []uint32{5, 4},
		},
		{
			Domain: "c.a..b.com",
			Result: nil,
		},
		{
			Domain: ".com",
			Result: nil,
		},
		{
			Domain: "com",
			Result: nil,
		},
		{
			Domain: "",
			Result: nil,
		},
		{
			Domain: "x.y.com",
			Result: []uint32{4, 6},
		},
	}
	g := NewDomainMatcherGroup()
	for _, pattern := range patterns {
		AddMatcherToGroup(g, DomainMatcher(pattern.Pattern), pattern.Value)
	}
	for _, testCase := range testCases {
		r := g.Match(testCase.Domain)
		if !reflect.DeepEqual(r, testCase.Result) {
			t.Error("Failed to match domain: ", testCase.Domain, ", expect ", testCase.Result, ", but got ", r)
		}
	}
}

func TestEmptyDomainMatcherGroup(t *testing.T) {
	g := NewDomainMatcherGroup()
	r := g.Match("example.com")
	if len(r) != 0 {
		t.Error("Expect [], but ", r)
	}
}
