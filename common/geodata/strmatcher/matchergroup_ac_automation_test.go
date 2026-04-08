package strmatcher_test

import (
	"reflect"
	"testing"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/geodata/strmatcher"
)

func TestACAutomatonMatcherGroup(t *testing.T) {
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
		ac := NewACAutomatonMatcherGroup()
		matcher, err := test.mType.New(test.pattern)
		common.Must(err)
		common.Must(AddMatcherToGroup(ac, matcher, 0))
		ac.Build()
		if m := ac.MatchAny(test.input); m != test.output {
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
			{
				pattern: "google.com",
				mType:   Substr,
			},
			{
				pattern: "vgoogle.com",
				mType:   Substr,
			},
		}
		ac := NewACAutomatonMatcherGroup()
		for _, test := range cases2Input {
			matcher, err := test.mType.New(test.pattern)
			common.Must(err)
			common.Must(AddMatcherToGroup(ac, matcher, 0))
		}
		ac.Build()
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
				res:     true,
			},
		}
		for _, test := range cases2Output {
			if m := ac.MatchAny(test.pattern); m != test.res {
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
		ac := NewACAutomatonMatcherGroup()
		for _, test := range cases3Input {
			matcher, err := test.mType.New(test.pattern)
			common.Must(err)
			common.Must(AddMatcherToGroup(ac, matcher, 0))
		}
		ac.Build()
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
			if m := ac.MatchAny(test.pattern); m != test.res {
				t.Error("unexpected output: ", m, " for test case ", test)
			}
		}
	}

	{
		cases4Input := []struct {
			pattern string
			mType   Type
		}{
			{
				pattern: "apis",
				mType:   Substr,
			},
			{
				pattern: "googleapis.com",
				mType:   Domain,
			},
		}
		ac := NewACAutomatonMatcherGroup()
		for _, test := range cases4Input {
			matcher, err := test.mType.New(test.pattern)
			common.Must(err)
			common.Must(AddMatcherToGroup(ac, matcher, 0))
		}
		ac.Build()
		cases4Output := []struct {
			pattern string
			res     bool
		}{
			{
				pattern: "gapis.com",
				res:     true,
			},
		}
		for _, test := range cases4Output {
			if m := ac.MatchAny(test.pattern); m != test.res {
				t.Error("unexpected output: ", m, " for test case ", test)
			}
		}
	}
}

func TestACAutomatonMatcherGroupSubstr(t *testing.T) {
	patterns := []struct {
		pattern string
		mType   Type
	}{
		{
			pattern: "apis",
			mType:   Substr,
		},
		{
			pattern: "google",
			mType:   Substr,
		},
		{
			pattern: "apis",
			mType:   Substr,
		},
	}
	cases := []struct {
		input  string
		output []uint32
	}{
		{
			input:  "google.com",
			output: []uint32{1},
		},
		{
			input:  "apis.com",
			output: []uint32{0, 2},
		},
		{
			input:  "googleapis.com",
			output: []uint32{1, 0, 2},
		},
		{
			input:  "fonts.googleapis.com",
			output: []uint32{1, 0, 2},
		},
		{
			input:  "apis.googleapis.com",
			output: []uint32{0, 2, 1, 0, 2},
		},
	}
	matcherGroup := NewACAutomatonMatcherGroup()
	for id, entry := range patterns {
		matcher, err := entry.mType.New(entry.pattern)
		common.Must(err)
		common.Must(AddMatcherToGroup(matcherGroup, matcher, uint32(id)))
	}
	matcherGroup.Build()
	for _, test := range cases {
		if r := matcherGroup.Match(test.input); !reflect.DeepEqual(r, test.output) {
			t.Error("unexpected output: ", r, " for test case ", test)
		}
	}
}

// See https://github.com/v2fly/v2ray-core/issues/92#issuecomment-673238489
func TestACAutomatonMatcherGroupAsIndexMatcher(t *testing.T) {
	rules := []struct {
		Type   Type
		Domain string
	}{
		// Regex not supported by ACAutomationMatcherGroup
		// {
		// 	Type:   Regex,
		// 	Domain: "apis\\.us$",
		// },
		{
			Type:   Substr,
			Domain: "apis",
		},
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
		{
			Type:   Substr,
			Domain: "apis",
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
			Output: []uint32{8, 3, 7, 4, 2, 6},
		},
		{
			Input:  "example.googleapis.com",
			Output: []uint32{3, 7, 4, 2, 6},
		},
		{
			Input:  "testapis.us",
			Output: []uint32{2, 6 /*, 1*/},
		},
		{
			Input:  "example.com",
			Output: []uint32{10, 4},
		},
	}
	matcherGroup := NewACAutomatonMatcherGroup()
	for i, rule := range rules {
		matcher, err := rule.Type.New(rule.Domain)
		common.Must(err)
		common.Must(AddMatcherToGroup(matcherGroup, matcher, uint32(i+2)))
	}
	matcherGroup.Build()
	for _, test := range cases {
		if m := matcherGroup.Match(test.Input); !reflect.DeepEqual(m, test.Output) {
			t.Error("unexpected output: ", m, " for test case ", test)
		}
	}
}
