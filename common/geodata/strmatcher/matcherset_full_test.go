package strmatcher_test

import (
	"reflect"
	"testing"

	. "github.com/xtls/xray-core/common/geodata/strmatcher"
)

func TestFullMatcherSet(t *testing.T) {
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
			Domain: "example.com",
			Result: true,
		},
		{
			Domain: "y.com",
			Result: false,
		},
		{
			Domain: "x.y.com",
			Result: true,
		},
	}
	s := NewFullMatcherSet()
	for _, pattern := range patterns {
		AddMatcherToSet(s, FullMatcher(pattern.Pattern))
	}
	for _, testCase := range testCases {
		r := s.MatchAny(testCase.Domain)
		if !reflect.DeepEqual(r, testCase.Result) {
			t.Error("Failed to match domain: ", testCase.Domain, ", expect ", testCase.Result, ", but got ", r)
		}
	}
}

func TestEmptyFullMatcherSet(t *testing.T) {
	s := NewFullMatcherSet()
	r := s.MatchAny("example.com")
	if r {
		t.Error("Expect false, but ", r)
	}
}
