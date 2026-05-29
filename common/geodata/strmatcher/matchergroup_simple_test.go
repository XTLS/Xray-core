package strmatcher_test

import (
	"reflect"
	"testing"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/geodata/strmatcher"
)

func TestSimpleMatcherGroup(t *testing.T) {
	patterns := []struct {
		pattern string
		mType   Type
	}{
		{
			pattern: "example.com",
			mType:   Domain,
		},
		{
			pattern: "example.com",
			mType:   Full,
		},
		{
			pattern: "example.com",
			mType:   Regex,
		},
	}
	cases := []struct {
		input  string
		output []uint32
	}{
		{
			input:  "www.example.com",
			output: []uint32{0, 2},
		},
		{
			input:  "example.com",
			output: []uint32{0, 1, 2},
		},
		{
			input:  "www.e3ample.com",
			output: []uint32{},
		},
		{
			input:  "xample.com",
			output: []uint32{},
		},
		{
			input:  "xexample.com",
			output: []uint32{2},
		},
		{
			input:  "examplexcom",
			output: []uint32{2},
		},
	}
	matcherGroup := &SimpleMatcherGroup{}
	for id, entry := range patterns {
		matcher, err := entry.mType.New(entry.pattern)
		common.Must(err)
		common.Must(AddMatcherToGroup(matcherGroup, matcher, uint32(id)))
	}
	for _, test := range cases {
		if r := matcherGroup.Match(test.input); !reflect.DeepEqual(r, test.output) {
			t.Error("unexpected output: ", r, " for test case ", test)
		}
	}
}
