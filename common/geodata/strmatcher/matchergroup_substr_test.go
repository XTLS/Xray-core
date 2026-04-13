package strmatcher_test

import (
	"reflect"
	"testing"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/geodata/strmatcher"
)

func TestSubstrMatcherGroup(t *testing.T) {
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
	matcherGroup := &SubstrMatcherGroup{}
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
