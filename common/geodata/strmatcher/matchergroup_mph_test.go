package strmatcher_test

import (
	"reflect"
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
