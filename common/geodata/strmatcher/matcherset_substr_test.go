package strmatcher_test

import (
	"reflect"
	"testing"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/geodata/strmatcher"
)

func TestSubstrMatcherSet(t *testing.T) {
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
		output bool
	}{
		{
			input:  "google.com",
			output: true,
		},
		{
			input:  "apis.com",
			output: true,
		},
		{
			input:  "googleapis.com",
			output: true,
		},
		{
			input:  "fonts.googleapis.com",
			output: true,
		},
		{
			input:  "apis.googleapis.com",
			output: true,
		},
		{
			input:  "baidu.com",
			output: false,
		},
		{
			input:  "goog",
			output: false,
		},
		{
			input:  "api",
			output: false,
		},
	}
	matcherSet := &SubstrMatcherSet{}
	for _, entry := range patterns {
		matcher, err := entry.mType.New(entry.pattern)
		common.Must(err)
		common.Must(AddMatcherToSet(matcherSet, matcher))
	}
	for _, test := range cases {
		if r := matcherSet.MatchAny(test.input); !reflect.DeepEqual(r, test.output) {
			t.Error("unexpected output: ", r, " for test case ", test)
		}
	}
}
