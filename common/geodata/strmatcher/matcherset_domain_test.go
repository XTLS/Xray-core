package strmatcher_test

import (
	"reflect"
	"testing"

	. "github.com/xtls/xray-core/common/geodata/strmatcher"
)

func TestDomainMatcherSet(t *testing.T) {
	patterns := []struct {
		Pattern string
	}{
		{
			Pattern: "example.com",
		},
		{
			Pattern: "google.com",
		},
		{
			Pattern: "x.a.com",
		},
		{
			Pattern: "a.b.com",
		},
		{
			Pattern: "c.a.b.com",
		},
		{
			Pattern: "x.y.com",
		},
		{
			Pattern: "x.y.com",
		},
	}
	testCases := []struct {
		Domain string
		Result bool
	}{
		{
			Domain: "x.example.com",
			Result: true,
		},
		{
			Domain: "y.com",
			Result: false,
		},
		{
			Domain: "a.b.com",
			Result: true,
		},
		{
			Domain: "c.a.b.com",
			Result: true,
		},
		{
			Domain: "c.a..b.com",
			Result: false,
		},
		{
			Domain: ".com",
			Result: false,
		},
		{
			Domain: "com",
			Result: false,
		},
		{
			Domain: "",
			Result: false,
		},
		{
			Domain: "x.y.com",
			Result: true,
		},
	}
	s := NewDomainMatcherSet()
	for _, pattern := range patterns {
		AddMatcherToSet(s, DomainMatcher(pattern.Pattern))
	}
	for _, testCase := range testCases {
		r := s.MatchAny(testCase.Domain)
		if !reflect.DeepEqual(r, testCase.Result) {
			t.Error("Failed to match domain: ", testCase.Domain, ", expect ", testCase.Result, ", but got ", r)
		}
	}
}

func TestEmptyDomainMatcherSet(t *testing.T) {
	s := NewDomainMatcherSet()
	r := s.MatchAny("example.com")
	if r {
		t.Error("Expect false, but ", r)
	}
}
