package strmatcher_test

import (
	"reflect"
	"testing"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/geodata/strmatcher"
)

func TestSimpleMatcherSet(t *testing.T) {
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
		output bool
	}{
		{
			input:  "www.example.com",
			output: true,
		},
		{
			input:  "example.com",
			output: true,
		},
		{
			input:  "www.e3ample.com",
			output: false,
		},
		{
			input:  "xample.com",
			output: false,
		},
		{
			input:  "xexample.com",
			output: true,
		},
		{
			input:  "examplexcom",
			output: true,
		},
	}
	matcherSet := &SimpleMatcherSet{}
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
